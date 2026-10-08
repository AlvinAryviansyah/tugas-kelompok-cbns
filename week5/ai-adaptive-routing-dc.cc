// =============================================================================
//  ai-adaptive-routing-dc.cc
//
//  Simulasi ns-3 untuk paper:
//    "AI-Optimized Adaptive Routing for High-Performance Data Centers:
//     A Predictive Framework for Dynamic Network Optimization"
//     (V. Hiremath, IEEE AIC 2025)
//
//  Tujuan: membandingkan STATIC ROUTING (jalur dipaku, tidak bisa menghindari
//  kongesti) dengan AI ADAPTIVE ROUTING (prediksi kongesti + pemindahan jalur
//  secara dinamis) pada tiga level beban: low / medium / high.
//  Metrik yang diukur sama seperti Fig 2, 3, dan 4 di paper:
//  throughput, latency, dan packet loss.
//
//  Empat layer arsitektur di Section III.A paper dipetakan ke kode seperti ini:
//    Layer 1  Data Collection      -> AiRoutingController::CollectMetrics()
//    Layer 2  Traffic Prediction   -> class CongestionPredictor
//    Layer 3  Routing Optimization -> AiRoutingController::AssignRoutes()
//    Layer 4  Feedback & Adjust    -> AiRoutingController::ApplyFeedback()
//
//  Cara pakai (dijalankan dari direktori root ns-3):
//    ./ns3 run "ai-adaptive-routing-dc --mode=static --traffic=high"
//    ./ns3 run "ai-adaptive-routing-dc --mode=ai     --traffic=high"
//    ./ns3 run "ai-adaptive-routing-dc --mode=ai --traffic=medium --simTime=6 --anim=1"
// =============================================================================

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("AiAdaptiveRoutingDc");

// =============================================================================
//  BAGIAN 1 - PARAMETER TOPOLOGI DAN SIMULASI
// =============================================================================

// Topologi leaf-spine: setiap leaf tersambung ke SEMUA spine, jadi antara dua
// leaf selalu ada N_SPINE jalur berbeda. Jalur alternatif inilah yang nanti
// dipilih oleh AI controller.
constexpr uint32_t N_SPINE = 2;
constexpr uint32_t N_LEAF = 4;
constexpr uint32_t HOSTS_PER_LEAF = 2;
constexpr uint32_t N_HOST = N_LEAF * HOSTS_PER_LEAF; // 8 host

// LAN host<->leaf dibuat lebar (1 Gbps) supaya BUKAN dia yang jadi bottleneck.
const char* const LAN_RATE = "1Gbps";
const char* const LAN_DELAY = "100us";

// Uplink leaf<->spine sengaja dibuat sempit. Di sinilah kongesti terjadi, dan
// di sinilah perbedaan static vs AI routing kelihatan.
const char* const UPLINK_RATE = "50Mbps";
const char* const UPLINK_DELAY = "500us";
constexpr double UPLINK_CAPACITY_BPS = 50e6;

// Buffer tiap port uplink. Kalau penuh -> paket di-drop (sumber packet loss).
const char* const QDISC_SIZE = "100p";
constexpr double QDISC_MAX_PKTS = 100.0;

// Periode kerja control loop AI (probe metrik -> prediksi -> ganti rute).
const Time CONTROL_INTERVAL = MilliSeconds(100);

constexpr uint16_t SINK_PORT = 9;
constexpr uint32_t PACKET_SIZE = 1024;

// Level beban per flow. Tiap leaf punya 2 host pengirim, jadi beban agregat
// per leaf = 2x nilai di bawah, sementara satu uplink hanya 50 Mbps:
//   low    :  2x5  = 10 Mbps -> jauh di bawah kapasitas, static & AI mirip
//   medium :  2x20 = 40 Mbps -> static 80% utilisasi 1 link, AI 40% di 2 link
//   high   :  2x40 = 80 Mbps -> static kelebihan beban (drop berat), AI aman
uint64_t
TrafficRateBps(const std::string& level)
{
    if (level == "low")
    {
        return 5000000;
    }
    if (level == "medium")
    {
        return 20000000;
    }
    if (level == "high")
    {
        return 40000000;
    }
    NS_FATAL_ERROR("Nilai --traffic harus low|medium|high, tapi dapat: " << level);
    return 0;
}

// =============================================================================
//  BAGIAN 2 - STRUKTUR DATA TOPOLOGI
// =============================================================================

// Satu uplink = satu link point-to-point dari sebuah leaf ke sebuah spine.
// Semua yang dibutuhkan controller untuk memantau dan memakai link ini
// dikumpulkan di sini supaya tidak perlu menelusuri objek ns-3 berulang kali.
struct Uplink
{
    uint32_t leafIface = 0;   // index interface IPv4 di sisi leaf
    Ipv4Address spineAddr;    // alamat sisi spine -> dipakai sebagai next-hop
    Ptr<QueueDisc> leafQdisc; // buffer di sisi leaf -> sensor kongesti kita
    uint32_t spineNodeId = 0; // untuk pewarnaan link di NetAnim
};

struct Topology
{
    NodeContainer spines;
    NodeContainer leaves;
    NodeContainer hosts;

    Uplink uplink[N_LEAF][N_SPINE];

    Ipv4Address hostAddr[N_HOST];    // alamat tiap host (tujuan rute)
    Ipv4Address leafLanAddr[N_LEAF]; // alamat leaf di LAN-nya (default gw host)

    static uint32_t LeafOfHost(uint32_t h)
    {
        return h / HOSTS_PER_LEAF;
    }
};

// Objek animasi disimpan di scope file karena fungsi pewarnaan periodik
// (dijadwalkan lewat Simulator::Schedule) perlu mengaksesnya.
std::unique_ptr<AnimationInterface> g_anim;

// =============================================================================
//  BAGIAN 3 - MEMBANGUN TOPOLOGI
// =============================================================================

void
BuildTopology(Topology& topo)
{
    // --- 3a. Buat semua node -------------------------------------------------
    topo.spines.Create(N_SPINE);
    topo.leaves.Create(N_LEAF);
    topo.hosts.Create(N_HOST);

    // --- 3b. Pasang TCP/IP stack --------------------------------------------
    // Penting: TIDAK memakai Ipv4GlobalRoutingHelper. Kalau global routing
    // dipakai, dia akan menghitung rute sendiri dan keputusan controller kita
    // jadi tidak berarti. Semua rute di sini diisi manual sebagai static route.
    InternetStackHelper stack;
    stack.Install(topo.spines);
    stack.Install(topo.leaves);
    stack.Install(topo.hosts);

    // --- 3c. LAN host<->leaf (mirip ToR switch dengan beberapa server) -------
    // Dibuat sebagai CSMA agar satu leaf + host-hostnya berada di satu subnet
    // 10.1.<leaf>.0/24. Ini membuat tabel rute jauh lebih sederhana.
    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue(LAN_RATE));
    csma.SetChannelAttribute("Delay", StringValue(LAN_DELAY));

    Ipv4AddressHelper lanAddr;
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        // Urutan node penting: leaf dulu, lalu host-hostnya. Dengan begitu
        // leaf selalu mendapat alamat .1 dan host mendapat .2, .3, dst.
        NodeContainer lanNodes;
        lanNodes.Add(topo.leaves.Get(i));
        for (uint32_t k = 0; k < HOSTS_PER_LEAF; ++k)
        {
            lanNodes.Add(topo.hosts.Get(i * HOSTS_PER_LEAF + k));
        }

        NetDeviceContainer lanDevs = csma.Install(lanNodes);

        std::ostringstream base;
        base << "10.1." << i << ".0";
        lanAddr.SetBase(Ipv4Address(base.str().c_str()), Ipv4Mask("255.255.255.0"));
        Ipv4InterfaceContainer lanIfs = lanAddr.Assign(lanDevs);

        topo.leafLanAddr[i] = lanIfs.GetAddress(0);
        for (uint32_t k = 0; k < HOSTS_PER_LEAF; ++k)
        {
            topo.hostAddr[i * HOSTS_PER_LEAF + k] = lanIfs.GetAddress(1 + k);
        }
    }

    // --- 3d. Uplink leaf<->spine (titik bottleneck) --------------------------
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue(UPLINK_RATE));
    p2p.SetChannelAttribute("Delay", StringValue(UPLINK_DELAY));

    // Antrian internal device dikecilkan menjadi 1 paket supaya hampir semua
    // buffering terjadi di queue disc yang kita pantau. Kalau dibiarkan pada
    // default 100 paket, separuh antrian tersembunyi di dalam device sehingga
    // sinyal panjang antrian jadi tumpul dan latency bertambah tanpa terdeteksi
    // oleh controller.
    p2p.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("1p"));

    // Buffer dipasang eksplisit sebagai FIFO berukuran tetap. Default ns-3
    // adalah FqCoDel yang punya AQM; FIFO dipilih supaya sinyal "antrian penuh
    // lalu drop" bersih dan mudah dibaca sebagai indikator kongesti.
    TrafficControlHelper tch;
    tch.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize", StringValue(QDISC_SIZE));

    Ipv4AddressHelper upAddr;
    upAddr.SetBase("10.2.0.0", Ipv4Mask("255.255.255.252"));

    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            // Device index 0 = sisi leaf, index 1 = sisi spine.
            NetDeviceContainer devs =
                p2p.Install(topo.leaves.Get(i), topo.spines.Get(s));

            // Queue disc dipasang di kedua ujung: sisi leaf untuk arah naik
            // (host -> spine), sisi spine untuk arah turun (spine -> host).
            QueueDiscContainer qdiscs = tch.Install(devs);

            Ipv4InterfaceContainer ifs = upAddr.Assign(devs);
            upAddr.NewNetwork();

            // Index interface diambil dari hasil Assign, bukan diasumsikan,
            // supaya tetap benar kalau urutan pemasangan device diubah.
            topo.uplink[i][s].leafIface = ifs.Get(0).second;
            topo.uplink[i][s].spineAddr = ifs.GetAddress(1);
            topo.uplink[i][s].leafQdisc = qdiscs.Get(0);
            topo.uplink[i][s].spineNodeId = topo.spines.Get(s)->GetId();
        }
    }
}

// =============================================================================
//  BAGIAN 4 - ROUTING
// =============================================================================

Ptr<Ipv4StaticRouting>
GetStaticRouting(Ptr<Node> node)
{
    Ipv4StaticRoutingHelper helper;
    return helper.GetStaticRouting(node->GetObject<Ipv4>());
}

// Mengganti rute /32 ke satu host: hapus dulu entri lama ke tujuan yang sama,
// lalu pasang yang baru. Tanpa penghapusan, ns-3 akan menganggap dua entri
// dengan tujuan sama sebagai ECMP dan memilih salah satu secara acak, sehingga
// keputusan controller tidak lagi deterministik.
void
SetHostRoute(Ptr<Ipv4StaticRouting> routing,
             Ipv4Address dest,
             Ipv4Address nextHop,
             uint32_t iface)
{
    // Iterasi dari belakang karena RemoveRoute menggeser index.
    for (uint32_t k = routing->GetNRoutes(); k > 0; --k)
    {
        Ipv4RoutingTableEntry entry = routing->GetRoute(k - 1);
        if (entry.IsHost() && entry.GetDest() == dest)
        {
            routing->RemoveRoute(k - 1);
        }
    }
    routing->AddHostRouteTo(dest, nextHop, iface);
}

void
InstallRouting(Topology& topo)
{
    // --- 4a. Host: cukup default route ke leaf-nya ---------------------------
    // Host tidak mengambil keputusan routing apa pun; semua diserahkan ke leaf.
    for (uint32_t h = 0; h < N_HOST; ++h)
    {
        uint32_t leaf = Topology::LeafOfHost(h);
        // Interface 1 = interface CSMA (interface 0 selalu loopback).
        GetStaticRouting(topo.hosts.Get(h))->SetDefaultRoute(topo.leafLanAddr[leaf], 1);
    }

    // --- 4b. Spine: rute statis ke setiap subnet leaf ------------------------
    // Spine hanya meneruskan ke bawah dan tidak pernah berubah, baik di mode
    // static maupun AI. Yang adaptif hanya keputusan di leaf.
    for (uint32_t s = 0; s < N_SPINE; ++s)
    {
        Ptr<Ipv4StaticRouting> routing = GetStaticRouting(topo.spines.Get(s));
        Ptr<Ipv4> spineIpv4 = topo.spines.Get(s)->GetObject<Ipv4>();

        for (uint32_t i = 0; i < N_LEAF; ++i)
        {
            std::ostringstream net;
            net << "10.1." << i << ".0";

            // Interface index di sisi spine dicari dari alamatnya sendiri,
            // bukan diasumsikan dari urutan pemasangan link.
            Ipv4Address ownAddr = topo.uplink[i][s].spineAddr;
            int32_t spineIface = spineIpv4->GetInterfaceForAddress(ownAddr);
            NS_ABORT_MSG_IF(spineIface < 0, "Interface spine tidak ditemukan untuk " << ownAddr);

            // Pada /30 berisi dua host, alamat leaf = alamat spine - 1, karena
            // saat Ipv4AddressHelper::Assign urutannya leaf dulu lalu spine.
            Ipv4Address leafNextHop(ownAddr.Get() - 1);

            routing->AddNetworkRouteTo(Ipv4Address(net.str().c_str()),
                                       Ipv4Mask("255.255.255.0"),
                                       leafNextHop,
                                       static_cast<uint32_t>(spineIface));
        }
    }

    // --- 4c. Leaf: rute awal ke setiap host remote, semua lewat Spine0 -------
    // Ini adalah baseline "static shortest-path dengan tie-break tetap" yang
    // dikritik paper: ada dua jalur setara tapi hanya satu yang dipakai,
    // sehingga Spine1 menganggur dan Spine0 jadi bottleneck.
    // Di mode AI, entri inilah yang nanti ditulis ulang oleh controller.
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        Ptr<Ipv4StaticRouting> routing = GetStaticRouting(topo.leaves.Get(i));
        for (uint32_t h = 0; h < N_HOST; ++h)
        {
            if (Topology::LeafOfHost(h) == i)
            {
                continue; // host lokal sudah tercakup rute subnet LAN
            }
            SetHostRoute(routing,
                         topo.hostAddr[h],
                         topo.uplink[i][0].spineAddr,
                         topo.uplink[i][0].leafIface);
        }
    }
}

// =============================================================================
//  BAGIAN 5 - LAYER 2: PREDIKSI KONGESTI
// =============================================================================

// Model prediktif ringan sesuai "Traffic Prediction Layer" di paper.
// Dua komponen:
//   1. EWMA  -> meredam noise dari pengukuran sesaat
//   2. slope -> arah tren, dipakai untuk ekstrapolasi satu interval ke depan
// Jadi keputusan routing dibuat berdasarkan kondisi YANG DIPREDIKSI, bukan
// kondisi yang sudah terjadi. Inilah bedanya dengan reactive load balancing.
class CongestionPredictor
{
  public:
    explicit CongestionPredictor(double alpha = 0.4)
        : m_alpha(alpha)
    {
    }

    void Update(double sample)
    {
        if (!m_initialized)
        {
            m_ewma = sample;
            m_prevEwma = sample;
            m_initialized = true;
            return;
        }
        m_prevEwma = m_ewma;
        m_ewma = m_alpha * sample + (1.0 - m_alpha) * m_ewma;
    }

    // Perkiraan beban pada interval berikutnya.
    double Predict() const
    {
        double slope = m_ewma - m_prevEwma;
        return std::max(0.0, m_ewma + slope);
    }

    double Current() const
    {
        return m_ewma;
    }

  private:
    double m_alpha;
    double m_ewma = 0.0;
    double m_prevEwma = 0.0;
    bool m_initialized = false;
};

// =============================================================================
//  BAGIAN 6 - CONTROLLER AI (LAYER 1, 3, DAN 4)
// =============================================================================

class AiRoutingController
{
  public:
    explicit AiRoutingController(Topology* topo)
        : m_topo(topo)
    {
    }

    // Mulai control loop dan pasang sensor trafik.
    void Start();

    // Dipanggil dari trace Ipv4L3Protocol setiap kali sebuah leaf meneruskan
    // paket. Dipakai untuk mengukur demand per tujuan (Layer 1).
    void RecordForward(uint32_t leafIdx, const Ipv4Header& header, uint32_t bytes);

    uint32_t GetRouteChanges() const
    {
        return m_totalRouteChanges;
    }

  private:
    void ControlStep();   // satu siklus penuh: collect -> predict -> assign -> feedback
    void CollectMetrics(); // Layer 1
    void AssignRoutes();   // Layer 3
    void ApplyFeedback();  // Layer 4

    Topology* m_topo;

    // --- state Layer 1: pembacaan terakhir tiap uplink ----------------------
    uint64_t m_lastSentBytes[N_LEAF][N_SPINE] = {};
    uint32_t m_lastDropped[N_LEAF][N_SPINE] = {};
    double m_dropRate[N_LEAF][N_SPINE] = {};   // drop per interval, dinormalisasi
    double m_utilization[N_LEAF][N_SPINE] = {}; // utilisasi terukur 0..1+

    // --- state Layer 1: demand per tujuan, diukur dari trace forwarding -----
    // key = Ipv4Address::Get() dari host tujuan
    std::map<uint32_t, uint64_t> m_bytesThisInterval[N_LEAF];
    std::map<uint32_t, double> m_demandEwma[N_LEAF];

    // --- state Layer 2 -----------------------------------------------------
    CongestionPredictor m_predictor[N_LEAF][N_SPINE];

    // --- state Layer 3: pemetaan tujuan -> spine yang sedang dipakai --------
    std::map<uint32_t, uint32_t> m_assignment[N_LEAF];

    // --- state Layer 4: parameter yang di-tuning sendiri oleh feedback ------
    double m_lossWeight = 2.0;  // seberapa berat drop dihukum dalam cost
    double m_hysteresis = 0.15; // ambang minimal perbaikan agar rute diganti
    double m_prevTotalDropRate = 0.0;
    uint32_t m_changesLastStep = 0; // jumlah rute yang diubah pada siklus lalu
    uint32_t m_totalRouteChanges = 0;
};

// Trace sink harus berupa fungsi bebas karena MakeBoundCallback tidak bisa
// mengikat argumen tambahan ke member function.
void
LeafForwardTraceSink(AiRoutingController* ctrl,
                     uint32_t leafIdx,
                     const Ipv4Header& header,
                     Ptr<const Packet> packet,
                     uint32_t /* interface */)
{
    ctrl->RecordForward(leafIdx, header, packet->GetSize());
}

void
AiRoutingController::Start()
{
    // Catat kondisi awal: semua tujuan remote saat ini lewat Spine0, sesuai
    // tabel rute yang dipasang InstallRouting(). Peta ini sekaligus menjadi
    // daftar tujuan yang boleh dipindah-pindah oleh controller.
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t h = 0; h < N_HOST; ++h)
        {
            if (Topology::LeafOfHost(h) == i)
            {
                continue; // host lokal tidak perlu melewati spine
            }
            m_assignment[i][m_topo->hostAddr[h].Get()] = 0;
        }
    }

    // Pasang sensor di setiap leaf: trace "UnicastForward" dipicu tiap kali
    // leaf meneruskan paket, lengkap dengan header IP-nya. Dari sini kita tahu
    // berapa byte per tujuan -> itulah demand yang dipakai saat membagi beban.
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        Ptr<Ipv4L3Protocol> l3 = m_topo->leaves.Get(i)->GetObject<Ipv4L3Protocol>();
        l3->TraceConnectWithoutContext("UnicastForward",
                                       MakeBoundCallback(&LeafForwardTraceSink, this, i));
    }

    Simulator::Schedule(CONTROL_INTERVAL, &AiRoutingController::ControlStep, this);
}

void
AiRoutingController::RecordForward(uint32_t leafIdx, const Ipv4Header& header, uint32_t bytes)
{
    uint32_t dest = header.GetDestination().Get();

    // Hanya hitung tujuan remote (yang punya host route dan benar-benar bisa
    // dipindah jalurnya). Paket arah turun menuju host lokal diabaikan.
    if (m_assignment[leafIdx].find(dest) == m_assignment[leafIdx].end())
    {
        return;
    }
    m_bytesThisInterval[leafIdx][dest] += bytes;
}

void
AiRoutingController::ControlStep()
{
    CollectMetrics(); // Layer 1: baca kondisi jaringan saat ini

    // Jejak diagnostik (aktif dengan --verbose=1). Menampilkan utilisasi yang
    // TERUKUR berdampingan dengan nilai yang DIPREDIKSI, sehingga bisa dicek
    // apakah predictor benar-benar mendahului kongesti dan bukan sekadar
    // bereaksi setelah antrian penuh.
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            NS_LOG_INFO(Simulator::Now().GetSeconds()
                        << "s  Leaf" << i << "->Spine" << s << "  util_terukur="
                        << m_utilization[i][s] << "  ewma=" << m_predictor[i][s].Current()
                        << "  prediksi=" << m_predictor[i][s].Predict()
                        << "  drop=" << m_dropRate[i][s]);
        }
    }

    // Layer 4 dijalankan SEBELUM Layer 3 di dalam satu siklus. Yang dievaluasi
    // adalah dampak keputusan siklus SEBELUMNYA terhadap metrik yang baru saja
    // dibaca. Kalau urutannya dibalik, feedback akan menilai keputusan yang
    // efeknya belum sempat muncul di jaringan.
    ApplyFeedback(); // Layer 4: evaluasi hasil, sesuaikan parameter controller
    AssignRoutes();  // Layer 2 + 3: prediksi, lalu tulis ulang rute

    Simulator::Schedule(CONTROL_INTERVAL, &AiRoutingController::ControlStep, this);
}

// -----------------------------------------------------------------------------
//  LAYER 1 - DATA COLLECTION
// -----------------------------------------------------------------------------
void
AiRoutingController::CollectMetrics()
{
    const double intervalSec = CONTROL_INTERVAL.GetSeconds();

    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            Ptr<QueueDisc> qd = m_topo->uplink[i][s].leafQdisc;
            QueueDisc::Stats stats = qd->GetStats();

            // (a) Utilisasi link: byte terkirim pada interval ini dibagi
            //     kapasitas link selama interval yang sama.
            uint64_t sentDelta = stats.nTotalSentBytes - m_lastSentBytes[i][s];
            m_lastSentBytes[i][s] = stats.nTotalSentBytes;
            double util = (sentDelta * 8.0) / (UPLINK_CAPACITY_BPS * intervalSec);

            // (b) Okupansi buffer sesaat. Antrian yang mulai menumpuk adalah
            //     tanda kongesti paling awal, muncul sebelum link benar-benar
            //     saturasi, jadi berguna sebagai sinyal dini.
            double queueOccupancy = qd->GetNPackets() / QDISC_MAX_PKTS;

            // (c) Paket yang di-drop pada interval ini.
            uint32_t dropDelta = stats.nTotalDroppedPackets - m_lastDropped[i][s];
            m_lastDropped[i][s] = stats.nTotalDroppedPackets;

            m_utilization[i][s] = util;
            m_dropRate[i][s] = dropDelta / QDISC_MAX_PKTS;

            // Sinyal gabungan yang diumpankan ke predictor. Antrian diberi
            // bobot 0.5 agar tidak mendominasi utilisasi.
            m_predictor[i][s].Update(util + 0.5 * queueOccupancy);
        }

        // Demand per tujuan juga di-EWMA supaya burst sesaat tidak langsung
        // memicu perpindahan rute.
        for (auto& kv : m_bytesThisInterval[i])
        {
            double bps = (kv.second * 8.0) / intervalSec;
            double& ewma = m_demandEwma[i][kv.first];
            ewma = 0.4 * bps + 0.6 * ewma;
        }
        // Tujuan yang tidak mengirim apa pun pada interval ini harus meluruh,
        // bukan tetap pada nilai lamanya.
        for (auto& kv : m_demandEwma[i])
        {
            if (m_bytesThisInterval[i].find(kv.first) == m_bytesThisInterval[i].end())
            {
                kv.second *= 0.6;
            }
        }
        m_bytesThisInterval[i].clear();
    }
}

// -----------------------------------------------------------------------------
//  LAYER 3 - ROUTING OPTIMIZATION
// -----------------------------------------------------------------------------
void
AiRoutingController::AssignRoutes()
{
    m_changesLastStep = 0;

    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        Ptr<Ipv4StaticRouting> routing = GetStaticRouting(m_topo->leaves.Get(i));

        // (a) Biaya awal tiap uplink = beban yang DIPREDIKSI untuk interval
        //     berikutnya, ditambah penalti kalau link itu sedang membuang paket.
        double cost[N_SPINE];
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            cost[s] = m_predictor[i][s].Predict() + m_lossWeight * m_dropRate[i][s];
        }

        // (b) Urutkan tujuan dari demand terbesar ke terkecil. Greedy
        //     least-loaded akan jauh lebih seimbang kalau flow besar
        //     ditempatkan lebih dulu (prinsip yang sama dengan bin packing).
        std::vector<std::pair<double, uint32_t>> byDemand;
        byDemand.reserve(m_assignment[i].size());
        for (const auto& kv : m_assignment[i])
        {
            double demand = 0.0;
            auto it = m_demandEwma[i].find(kv.first);
            if (it != m_demandEwma[i].end())
            {
                demand = it->second;
            }
            byDemand.emplace_back(demand, kv.first);
        }
        std::sort(byDemand.begin(), byDemand.end(), std::greater<>());

        // (c) Tempatkan setiap tujuan pada uplink dengan biaya terendah, lalu
        //     tambahkan demand-nya ke biaya uplink tersebut. Penambahan inilah
        //     yang membuat tujuan berikutnya memilih uplink lain, sehingga
        //     beban tersebar alih-alih semuanya pindah ke satu link.
        for (const auto& item : byDemand)
        {
            uint32_t dest = item.second;
            uint32_t current = m_assignment[i][dest];

            uint32_t best = 0;
            for (uint32_t s = 1; s < N_SPINE; ++s)
            {
                if (cost[s] < cost[best])
                {
                    best = s;
                }
            }

            // Histeresis: hanya pindah kalau keuntungannya cukup besar.
            // Tanpa ini rute akan bolak-balik setiap 100 ms (route flapping)
            // dan justru memperburuk latency.
            if (cost[current] <= cost[best] + m_hysteresis)
            {
                best = current;
            }

            // Demand dinormalisasi ke satuan yang sama dengan cost (fraksi
            // kapasitas link) supaya bisa dijumlahkan langsung.
            double normalizedDemand = item.first / UPLINK_CAPACITY_BPS;
            cost[best] += normalizedDemand;

            if (best != current)
            {
                SetHostRoute(routing,
                             Ipv4Address(dest),
                             m_topo->uplink[i][best].spineAddr,
                             m_topo->uplink[i][best].leafIface);
                m_assignment[i][dest] = best;
                ++m_changesLastStep;
                ++m_totalRouteChanges;

                NS_LOG_INFO(Simulator::Now().GetSeconds()
                            << "s  Leaf" << i << " -> " << Ipv4Address(dest)
                            << " dipindah ke Spine" << best);
            }
        }
    }
}

// -----------------------------------------------------------------------------
//  LAYER 4 - FEEDBACK & ADJUSTMENT
// -----------------------------------------------------------------------------
void
AiRoutingController::ApplyFeedback()
{
    // Evaluasi hasil keputusan sebelumnya memakai total drop sebagai reward
    // negatif, lalu sesuaikan parameter controller:
    //   - drop naik setelah rute diubah  -> keputusan tadi merugikan, jadi
    //     controller dibuat lebih konservatif (histeresis & penalti loss naik)
    //   - jaringan bersih tanpa drop     -> controller boleh lebih responsif
    double totalDropRate = 0.0;
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            totalDropRate += m_dropRate[i][s];
        }
    }

    if (m_changesLastStep > 0 && totalDropRate > m_prevTotalDropRate)
    {
        m_hysteresis = std::min(0.50, m_hysteresis * 1.2);
        m_lossWeight = std::min(8.0, m_lossWeight * 1.1);
    }
    else if (totalDropRate == 0.0)
    {
        m_hysteresis = std::max(0.05, m_hysteresis * 0.98);
        m_lossWeight = std::max(1.0, m_lossWeight * 0.99);
    }

    m_prevTotalDropRate = totalDropRate;
}

// =============================================================================
//  BAGIAN 7 - TRAFIK
// =============================================================================

// Pola trafik: host h mengirim ke host (h+2) mod N_HOST. Dengan 2 host per leaf,
// pergeseran 2 memastikan pengirim dan penerima SELALU berada di leaf berbeda,
// jadi semua trafik harus melewati lapisan spine. Di situlah kontensi terjadi.
//
// Dipakai UDP constant bit rate, bukan TCP, karena TCP akan menurunkan laju
// kirimnya sendiri saat terjadi kongesti sehingga packet loss jadi tersembunyi.
// Paper mengukur throughput, latency, DAN packet loss pada beban tetap, jadi
// beban yang ditawarkan harus konstan.
void
InstallTraffic(Topology& topo, uint64_t rateBps, Time appStart, Time appStop)
{
    // Satu packet sink di setiap host sebagai penerima.
    PacketSinkHelper sinkHelper("ns3::UdpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), SINK_PORT));
    ApplicationContainer sinks = sinkHelper.Install(topo.hosts);
    sinks.Start(Seconds(0.5));
    sinks.Stop(appStop + Seconds(1.0));

    for (uint32_t h = 0; h < N_HOST; ++h)
    {
        uint32_t dst = (h + 2) % N_HOST;

        OnOffHelper onoff("ns3::UdpSocketFactory",
                          InetSocketAddress(topo.hostAddr[dst], SINK_PORT));
        // OnTime=1 dan OffTime=0 berarti aplikasi mengirim terus tanpa jeda.
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        onoff.SetAttribute("DataRate", DataRateValue(DataRate(rateBps)));
        onoff.SetAttribute("PacketSize", UintegerValue(PACKET_SIZE));

        ApplicationContainer app = onoff.Install(topo.hosts.Get(h));
        // Start di-stagger sedikit agar semua flow tidak mulai pada detik yang
        // sama persis (menghindari sinkronisasi artifisial).
        app.Start(appStart + MilliSeconds(10 * h));
        app.Stop(appStop);
    }
}

// =============================================================================
//  BAGIAN 8 - VISUALISASI NETANIM
// =============================================================================

// Tata letak tiga baris: spine di atas, leaf di tengah, host di bawah.
// Posisi diisi manual karena tanpa mobility model semua node akan menumpuk
// di titik (0,0) dan animasinya tidak bisa dibaca.
void
SetupAnimationLayout(Topology& topo)
{
    const double spineY = 10.0;
    const double leafY = 40.0;
    const double hostY = 70.0;

    for (uint32_t s = 0; s < N_SPINE; ++s)
    {
        Ptr<Node> node = topo.spines.Get(s);
        double x = 35.0 + s * 40.0;
        AnimationInterface::SetConstantPosition(node, x, spineY);
        g_anim->UpdateNodeDescription(node, "Spine" + std::to_string(s));
        g_anim->UpdateNodeColor(node, 200, 30, 30); // merah
    }

    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        Ptr<Node> node = topo.leaves.Get(i);
        double x = 10.0 + i * 25.0;
        AnimationInterface::SetConstantPosition(node, x, leafY);
        g_anim->UpdateNodeDescription(node, "Leaf" + std::to_string(i));
        g_anim->UpdateNodeColor(node, 30, 90, 220); // biru
    }

    for (uint32_t h = 0; h < N_HOST; ++h)
    {
        Ptr<Node> node = topo.hosts.Get(h);
        uint32_t leaf = Topology::LeafOfHost(h);
        uint32_t slot = h % HOSTS_PER_LEAF;
        double x = 4.0 + leaf * 25.0 + slot * 12.0;
        AnimationInterface::SetConstantPosition(node, x, hostY);
        g_anim->UpdateNodeDescription(node, "Host" + std::to_string(h));
        g_anim->UpdateNodeColor(node, 40, 170, 60); // hijau
    }
}

// Pewarnaan dinamis sesuai tingkat kongesti, dijalankan di kedua mode supaya
// perbedaannya langsung terlihat di animasi:
//   mode static -> Spine0 memerah, Spine1 tetap hijau (menganggur)
//   mode AI     -> kedua spine berwarna mirip (beban terbagi)
// Fungsi ini punya penghitung byte-nya sendiri agar tidak mengganggu
// pembacaan milik controller.
void
UpdateAnimationColors(Topology* topo, std::vector<uint64_t>* lastBytes)
{
    const double intervalSec = CONTROL_INTERVAL.GetSeconds();

    double spineLoad[N_SPINE] = {};

    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        double leafLoad = 0.0;

        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            uint32_t idx = i * N_SPINE + s;
            Ptr<QueueDisc> qd = topo->uplink[i][s].leafQdisc;
            uint64_t sent = qd->GetStats().nTotalSentBytes;
            uint64_t delta = sent - (*lastBytes)[idx];
            (*lastBytes)[idx] = sent;

            double util = (delta * 8.0) / (UPLINK_CAPACITY_BPS * intervalSec);
            // Antrian yang menumpuk ikut dihitung agar link yang sudah
            // overload (offered load > kapasitas) tampil merah, bukan hanya
            // tampil 100% seperti link yang pas-pas saja.
            double pressure = util + qd->GetNPackets() / QDISC_MAX_PKTS;

            spineLoad[s] += pressure;
            leafLoad += pressure;

            // Label link menunjukkan utilisasi aktual tiap uplink, sehingga
            // pembagian beban oleh AI terbaca sebagai angka, bukan hanya warna.
            std::ostringstream label;
            label << std::fixed << std::setprecision(0) << (util * 100.0) << "%";
            g_anim->UpdateLinkDescription(topo->leaves.Get(i)->GetId(),
                                          topo->uplink[i][s].spineNodeId,
                                          label.str());
        }

        // Gradien hijau -> kuning -> merah berdasarkan tekanan rata-rata.
        double avg = std::min(1.0, leafLoad / N_SPINE);
        g_anim->UpdateNodeColor(topo->leaves.Get(i),
                                static_cast<uint8_t>(40 + 200 * avg),
                                static_cast<uint8_t>(190 - 150 * avg),
                                60);
    }

    for (uint32_t s = 0; s < N_SPINE; ++s)
    {
        double avg = std::min(1.0, spineLoad[s] / N_LEAF);
        g_anim->UpdateNodeColor(topo->spines.Get(s),
                                static_cast<uint8_t>(40 + 200 * avg),
                                static_cast<uint8_t>(190 - 150 * avg),
                                60);
    }

    Simulator::Schedule(CONTROL_INTERVAL, &UpdateAnimationColors, topo, lastBytes);
}

// =============================================================================
//  BAGIAN 9 - PENGUKURAN HASIL
// =============================================================================

struct Results
{
    double throughputMbps = 0.0;
    double meanDelayMs = 0.0;
    double lossPercent = 0.0;
    uint64_t txPackets = 0;
    uint64_t rxPackets = 0;
    double spineShare[N_SPINE] = {}; // persentase byte yang lewat tiap spine
};

// Menghitung tiga metrik di Fig 2/3/4 paper dari data FlowMonitor.
Results
CollectResults(Ptr<FlowMonitor> monitor, Topology& topo, double measuredSeconds)
{
    Results r;

    // Wajib dipanggil agar paket yang masih "in flight" di akhir simulasi
    // dihitung sebagai hilang, bukan diabaikan.
    monitor->CheckForLostPackets();

    uint64_t totalRxBytes = 0;
    Time totalDelay;

    for (const auto& kv : monitor->GetFlowStats())
    {
        const FlowMonitor::FlowStats& st = kv.second;
        r.txPackets += st.txPackets;
        r.rxPackets += st.rxPackets;
        totalRxBytes += st.rxBytes;
        totalDelay += st.delaySum;
    }

    r.throughputMbps = (totalRxBytes * 8.0) / (measuredSeconds * 1e6);
    r.meanDelayMs = (r.rxPackets > 0) ? (totalDelay.GetSeconds() * 1000.0 / r.rxPackets) : 0.0;

    // Selisih dihitung bertanda lalu dijepit ke nol. Tanpa ini, kalau rxPackets
    // sempat melebihi txPackets (bisa terjadi pada flow yang statistiknya
    // belum sinkron di akhir simulasi), aritmetika unsigned akan wrap around
    // dan menghasilkan packet loss yang kelihatan sangat besar.
    int64_t lost = static_cast<int64_t>(r.txPackets) - static_cast<int64_t>(r.rxPackets);
    lost = std::max<int64_t>(0, lost);
    r.lossPercent = (r.txPackets > 0) ? (100.0 * lost / r.txPackets) : 0.0;

    // Distribusi beban antar spine: angka inilah yang menjelaskan MENGAPA
    // AI routing lebih baik, yaitu karena kedua spine terpakai.
    double perSpine[N_SPINE] = {};
    double total = 0.0;
    for (uint32_t i = 0; i < N_LEAF; ++i)
    {
        for (uint32_t s = 0; s < N_SPINE; ++s)
        {
            double bytes = topo.uplink[i][s].leafQdisc->GetStats().nTotalSentBytes;
            perSpine[s] += bytes;
            total += bytes;
        }
    }
    for (uint32_t s = 0; s < N_SPINE; ++s)
    {
        r.spineShare[s] = (total > 0) ? (100.0 * perSpine[s] / total) : 0.0;
    }

    return r;
}

void
PrintResults(const std::string& mode, const std::string& traffic, const Results& r, uint32_t routeChanges)
{
    std::cout << "\n==================== HASIL SIMULASI ====================\n";
    std::cout << "  Mode routing      : " << mode << "\n";
    std::cout << "  Level trafik      : " << traffic << "\n";
    std::cout << "  --------------------------------------------------\n";
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "  Throughput        : " << r.throughputMbps << " Mbps\n";
    std::cout << "  Latency rata-rata : " << r.meanDelayMs << " ms\n";
    std::cout << "  Packet loss       : " << r.lossPercent << " %\n";
    std::cout << "  --------------------------------------------------\n";
    std::cout << "  Paket dikirim     : " << r.txPackets << "\n";
    std::cout << "  Paket diterima    : " << r.rxPackets << "\n";
    std::cout << std::setprecision(1);
    for (uint32_t s = 0; s < N_SPINE; ++s)
    {
        std::cout << "  Beban via Spine" << s << "  : " << r.spineShare[s] << " %\n";
    }
    std::cout << "  Perubahan rute    : " << routeChanges << "\n";
    std::cout << "========================================================\n\n";
}

// Menyimpan hasil ke CSV (append) supaya run-experiments.sh bisa mengumpulkan
// semua kombinasi ke satu file untuk diplot.
// Kolom spine di CSV ditulis eksplisit, jadi format ini terikat pada 2 spine.
static_assert(N_SPINE == 2, "Format kolom CSV dan plot_results.py mengasumsikan 2 spine");

void
AppendCsv(const std::string& path,
          const std::string& mode,
          const std::string& traffic,
          const Results& r,
          uint32_t routeChanges)
{
    bool needHeader = true;
    {
        std::ifstream probe(path);
        needHeader = !probe.good() || probe.peek() == std::ifstream::traits_type::eof();
    }

    std::ofstream out(path, std::ios::app);
    if (!out)
    {
        NS_LOG_WARN("Tidak bisa menulis CSV ke " << path);
        return;
    }
    if (needHeader)
    {
        out << "mode,traffic,throughput_mbps,latency_ms,loss_percent,"
            << "tx_packets,rx_packets,spine0_share,spine1_share,route_changes\n";
    }
    out << mode << "," << traffic << "," << std::fixed << std::setprecision(4)
        << r.throughputMbps << "," << r.meanDelayMs << "," << r.lossPercent << ","
        << r.txPackets << "," << r.rxPackets << "," << r.spineShare[0] << ","
        << r.spineShare[1] << "," << routeChanges << "\n";
}

// =============================================================================
//  BAGIAN 10 - MAIN
// =============================================================================

int
main(int argc, char* argv[])
{
    // --- 10a. Parameter dari command line -----------------------------------
    std::string mode = "ai";       // static | ai
    std::string traffic = "high";  // low | medium | high
    double simTime = 20.0;
    bool anim = false;
    std::string animFile = "";
    std::string csvFile = "dc-routing-results.csv";
    uint32_t seed = 1;
    bool verbose = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("mode", "Algoritma routing: static atau ai", mode);
    cmd.AddValue("traffic", "Level beban: low, medium, atau high", traffic);
    cmd.AddValue("simTime", "Durasi simulasi dalam detik", simTime);
    cmd.AddValue("anim", "Hasilkan file XML untuk NetAnim (1=ya)", anim);
    cmd.AddValue("animFile", "Nama file XML NetAnim", animFile);
    cmd.AddValue("csv", "File CSV untuk menyimpan hasil (kosong = tidak menyimpan)", csvFile);
    cmd.AddValue("seed", "Seed RNG", seed);
    cmd.AddValue("verbose", "Tampilkan log keputusan controller", verbose);
    cmd.Parse(argc, argv);

    if (mode != "static" && mode != "ai")
    {
        NS_FATAL_ERROR("Nilai --mode harus static atau ai, tapi dapat: " << mode);
    }
    if (verbose)
    {
        LogComponentEnable("AiAdaptiveRoutingDc", LOG_LEVEL_INFO);
    }
    RngSeedManager::SetSeed(seed);

    // Aplikasi dinyalakan setelah 1 detik dan dimatikan 1 detik sebelum
    // simulasi berakhir. Jendela di antaranya adalah fase steady-state yang
    // dipakai untuk menghitung metrik.
    if (simTime < 3.0)
    {
        NS_FATAL_ERROR("--simTime minimal 3 detik, tapi dapat: " << simTime);
    }
    const Time appStart = Seconds(1.0);
    const Time appStop = Seconds(simTime - 1.0);
    const double measuredSeconds = (appStop - appStart).GetSeconds();

    // --- 10b. Bangun jaringan ------------------------------------------------
    Topology topo;
    BuildTopology(topo);
    InstallRouting(topo); // kondisi awal: semua rute remote lewat Spine0
    InstallTraffic(topo, TrafficRateBps(traffic), appStart, appStop);

    // --- 10c. Aktifkan controller hanya pada mode AI ------------------------
    // Mode static tidak menjalankan control loop sama sekali, sehingga tabel
    // rute awal (semua ke Spine0) bertahan sepanjang simulasi.
    AiRoutingController controller(&topo);
    if (mode == "ai")
    {
        controller.Start();
    }

    // --- 10d. NetAnim --------------------------------------------------------
    std::vector<uint64_t> animLastBytes(N_LEAF * N_SPINE, 0);
    if (anim)
    {
        if (animFile.empty())
        {
            animFile = "anim-" + mode + "-" + traffic + ".xml";
        }

        g_anim = std::make_unique<AnimationInterface>(animFile);
        // Metadata paket membuat NetAnim bisa menampilkan isi tiap paket, tapi
        // ukuran XML melonjak drastis. Untuk animasi gunakan simTime pendek
        // (sekitar 5-8 detik), bukan 20 detik seperti run pengukuran.
        g_anim->EnablePacketMetadata(true);
        g_anim->SetMaxPktsPerTraceFile(5000000);

        SetupAnimationLayout(topo);
        Simulator::Schedule(CONTROL_INTERVAL, &UpdateAnimationColors, &topo, &animLastBytes);

        std::cout << "[NetAnim] File animasi akan ditulis ke: " << animFile << "\n";
        if (simTime > 10.0)
        {
            std::cout << "[NetAnim] Peringatan: simTime=" << simTime
                      << "s dengan packet metadata akan menghasilkan XML sangat besar.\n";
        }
    }

    // --- 10e. FlowMonitor untuk mengukur throughput/latency/loss ------------
    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> monitor = flowHelper.InstallAll();

    // --- 10f. Jalankan -------------------------------------------------------
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    Results results = CollectResults(monitor, topo, measuredSeconds);
    PrintResults(mode, traffic, results, controller.GetRouteChanges());
    if (!csvFile.empty())
    {
        AppendCsv(csvFile, mode, traffic, results, controller.GetRouteChanges());
        std::cout << "Hasil ditambahkan ke " << csvFile << "\n";
    }

    Simulator::Destroy();

    // AnimationInterface menutup dan menyelesaikan file XML pada destruktornya,
    // jadi harus dilepas setelah simulasi selesai.
    g_anim.reset();

    return 0;
}
