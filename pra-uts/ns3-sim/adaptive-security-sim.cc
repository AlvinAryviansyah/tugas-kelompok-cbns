/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * =====================================================================================
 *  adaptive-security-sim.cc
 *
 *  Simulasi NS-3 untuk penelitian:
 *  "AI-Driven Adaptive Routing based on Performance & Security Traffic Framework
 *   for Dynamic Network Traffic using NS-3"
 *  (Alvin Aryviansyah, Fajar Parlindungan, Muchd. Arief Wibowo)
 *
 *  Script ini mengimplementasikan Phase 0 (Validation) dan Phase 1 (Attack Simulation)
 *  dari Experimental Design:
 *
 *      Node 0      : Sender   (sumber data, UDP broadcast ke LAN)
 *      Node 1 - 4  : Receiver (penerima data, mencatat fitur keamanan per paket)
 *      Node 5      : Attacker (flooding / replay / spoofing, tergantung --scenario)
 *      Media       : CSMA LAN 100 Mbps
 *      Transport   : UDP port 9000
 *      Payload     : 400 / 800 / 1200 byte (parameter --payload)
 *
 *  Output yang dihasilkan (untuk Phase 2-5: ML / RL / evaluasi):
 *      1. <prefix>-<scenario>-anim.xml   -> dibuka di NetAnim (visualisasi)
 *      2. security-<scenario>.csv        -> fitur per-paket di sisi receiver
 *                                           (seq, claimed_src, actual_src, delay,
 *                                            is_duplicate, is_spoof, is_unauthorized)
 *      3. flowmon-<scenario>.csv / .xml  -> statistik FlowMonitor per flow
 *      4. summary-<scenario>.csv         -> ringkasan per receiver
 *                                           (PDR, throughput, delay, dup ratio, dll.)
 *
 *  Cara pakai (di dalam direktori ns-3, setelah file ini disalin ke scratch/):
 *      ./ns3 run "scratch/adaptive-security-sim --scenario=flooding --payload=800"
 *
 *  Lihat README.md untuk daftar parameter lengkap dan cara build NetAnim.
 * =====================================================================================
 */

// ---------------------------------------------------------------------------
// STEP 0. Include modul NS-3 yang dibutuhkan
// ---------------------------------------------------------------------------
#include "ns3/core-module.h"          // Simulator, Time, CommandLine, RNG, logging
#include "ns3/network-module.h"       // Node, Packet, Header, Socket, Address
#include "ns3/internet-module.h"      // InternetStackHelper, Ipv4, UDP socket factory
#include "ns3/csma-module.h"          // CsmaHelper (LAN 100 Mbps)
#include "ns3/applications-module.h"  // Application base class
#include "ns3/mobility-module.h"      // Posisi node (dibutuhkan NetAnim)
#include "ns3/netanim-module.h"       // AnimationInterface -> file XML NetAnim
#include "ns3/flow-monitor-module.h"  // FlowMonitor -> throughput, delay, loss

#include <deque>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("AdaptiveSecuritySim");

// ---------------------------------------------------------------------------
// STEP 1. Konstanta global sesuai Network Model pada laporan (Tabel 2.1)
// ---------------------------------------------------------------------------
static const uint16_t kUdpPort        = 9000; // Port UDP untuk data dissemination
static const uint32_t kSenderNodeId   = 0;    // Node 0 = sender resmi (authorized)
static const uint32_t kFirstRxNodeId  = 1;    // Receiver = node 1..4
static const uint32_t kNumReceivers   = 4;
static const uint32_t kAttackerNodeId = 5;    // Node 5 = attacker
static const uint32_t kTotalNodes     = 6;

// Skenario serangan sesuai Security/Attack Model pada laporan (Tabel 2.3)
enum class Scenario
{
  NORMAL,    // hanya traffic legitimate (baseline)
  FLOODING,  // attacker mengirim traffic dengan rate tinggi
  REPLAY,    // attacker mengirim ulang paket/sequence yang pernah lewat
  SPOOFING   // attacker memakai claimed identity palsu (mengaku sebagai sender)
};

// Konversi string argumen CLI -> enum Scenario
static bool
ParseScenario (const std::string &s, Scenario &out)
{
  if (s == "normal")   { out = Scenario::NORMAL;   return true; }
  if (s == "flooding") { out = Scenario::FLOODING; return true; }
  if (s == "replay")   { out = Scenario::REPLAY;   return true; }
  if (s == "spoofing") { out = Scenario::SPOOFING; return true; }
  return false;
}

// Helper: alamat IP 10.1.1.(k+1) dimiliki oleh node k, jadi node id = oktet terakhir - 1
static uint32_t
NodeIdFromIp (Ipv4Address ip)
{
  return (ip.Get () & 0xFF) - 1;
}

// ---------------------------------------------------------------------------
// STEP 2. Custom application header: AppTag
//
// Setiap paket data membawa header kecil (16 byte) berisi:
//   - seq      : nomor urut paket   -> dipakai untuk deteksi DUPLICATE (replay)
//   - srcId    : "claimed identity" -> dipakai untuk deteksi SPOOFING
//                (dibandingkan dengan IP sumber sebenarnya)
//   - txTimeNs : waktu kirim        -> dipakai untuk menghitung end-to-end delay
//
// Dengan header ini, fitur keamanan pada laporan (duplicate ratio, auth failure,
// spoof count) bisa diukur langsung di sisi receiver.
// ---------------------------------------------------------------------------
class AppTag : public Header
{
public:
  AppTag () : m_seq (0), m_srcId (0), m_txTimeNs (0) {}

  static TypeId
  GetTypeId ()
  {
    static TypeId tid = TypeId ("AppTag")
                            .SetParent<Header> ()
                            .SetGroupName ("Applications")
                            .AddConstructor<AppTag> ();
    return tid;
  }
  TypeId GetInstanceTypeId () const override { return GetTypeId (); }

  // Ukuran header di "kabel": 4 (seq) + 4 (srcId) + 8 (txTime) = 16 byte
  uint32_t GetSerializedSize () const override { return 4 + 4 + 8; }

  // Tulis field ke buffer paket (network byte order)
  void
  Serialize (Buffer::Iterator start) const override
  {
    start.WriteHtonU32 (m_seq);
    start.WriteHtonU32 (m_srcId);
    start.WriteHtonU64 (m_txTimeNs);
  }

  // Baca field dari buffer paket
  uint32_t
  Deserialize (Buffer::Iterator start) override
  {
    m_seq      = start.ReadNtohU32 ();
    m_srcId    = start.ReadNtohU32 ();
    m_txTimeNs = start.ReadNtohU64 ();
    return GetSerializedSize ();
  }

  // Dipakai NetAnim (EnablePacketMetadata) dan logging
  void
  Print (std::ostream &os) const override
  {
    os << "seq=" << m_seq << " src=" << m_srcId << " tx=" << m_txTimeNs << "ns";
  }

  void     SetSeq (uint32_t v)     { m_seq = v; }
  void     SetSrcId (uint32_t v)   { m_srcId = v; }
  void     SetTxTime (Time t)      { m_txTimeNs = static_cast<uint64_t> (t.GetNanoSeconds ()); }
  uint32_t GetSeq () const         { return m_seq; }
  uint32_t GetSrcId () const       { return m_srcId; }
  Time     GetTxTime () const      { return NanoSeconds (m_txTimeNs); }

private:
  uint32_t m_seq;
  uint32_t m_srcId;
  uint64_t m_txTimeNs;
};
NS_OBJECT_ENSURE_REGISTERED (AppTag);

// ---------------------------------------------------------------------------
// STEP 3. SenderApp (Node 0) - sumber data legitimate
//
// Mengirim paket UDP ke alamat broadcast LAN (10.1.1.255:9000) dengan rate
// konstan (--legitRate Mbps) + sedikit jitter acak agar hasil bervariasi
// antar --seed. Setiap paket diberi AppTag dengan seq naik dan srcId = 0.
// ---------------------------------------------------------------------------
class SenderApp : public Application
{
public:
  SenderApp () : m_payload (400), m_rateMbps (5.0), m_seq (0), m_running (false) {}

  void
  Setup (Address dest, uint32_t payloadBytes, double rateMbps)
  {
    m_dest     = dest;
    m_payload  = payloadBytes;
    m_rateMbps = rateMbps;
    m_jitter   = CreateObject<UniformRandomVariable> ();
    m_jitter->SetAttribute ("Min", DoubleValue (0.9)); // jitter +-10 %
    m_jitter->SetAttribute ("Max", DoubleValue (1.1));
  }

  uint32_t GetSentCount () const { return m_seq; }

private:
  // Dipanggil otomatis oleh Simulator pada app->SetStartTime(...)
  void
  StartApplication () override
  {
    m_running = true;
    // 3a. Buat UDP socket di node ini
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Bind ();
    // 3b. Izinkan pengiriman ke alamat broadcast (wajib untuk 10.1.1.255)
    m_socket->SetAllowBroadcast (true);
    // 3c. Kirim paket pertama
    SendPacket ();
  }

  // Dipanggil otomatis oleh Simulator pada app->SetStopTime(...)
  void
  StopApplication () override
  {
    m_running = false;
    Simulator::Cancel (m_sendEvent);
    if (m_socket)
      {
        m_socket->Close ();
      }
  }

  void
  SendPacket ()
  {
    if (!m_running)
      {
        return;
      }

    // 3d. Buat paket berisi payload dummy sebesar --payload byte
    Ptr<Packet> pkt = Create<Packet> (m_payload);

    // 3e. Tempelkan AppTag: seq bertambah, identitas = sender (0), waktu kirim = sekarang
    AppTag tag;
    tag.SetSeq (++m_seq);
    tag.SetSrcId (kSenderNodeId);
    tag.SetTxTime (Simulator::Now ());
    pkt->AddHeader (tag);

    // 3f. Kirim ke alamat broadcast -> diterima semua receiver (dan attacker yang menyadap)
    m_socket->SendTo (pkt, 0, m_dest);

    // 3g. Jadwalkan paket berikutnya: interval = ukuran_bit / rate (+ jitter)
    double   intervalSec = (m_payload * 8.0) / (m_rateMbps * 1e6);
    Time     next        = Seconds (intervalSec * m_jitter->GetValue ());
    m_sendEvent          = Simulator::Schedule (next, &SenderApp::SendPacket, this);
  }

  Ptr<Socket>                 m_socket;
  Address                     m_dest;
  uint32_t                    m_payload;
  double                      m_rateMbps;
  uint32_t                    m_seq;
  bool                        m_running;
  EventId                     m_sendEvent;
  Ptr<UniformRandomVariable>  m_jitter;
};

// ---------------------------------------------------------------------------
// STEP 4. ReceiverApp (Node 1-4) - penerima data + pencatat fitur keamanan
//
// Setiap paket yang diterima diperiksa:
//   is_duplicate    : pasangan (claimed_src, seq) sudah pernah diterima  -> indikasi REPLAY
//   is_spoof        : claimed_src != node pemilik IP sumber sebenarnya   -> indikasi SPOOFING
//   is_unauthorized : IP sumber sebenarnya bukan sender resmi (node 0)   -> "unauthorized
//                     packet acceptance" (metrik security pada laporan)
// Semua baris ditulis ke security-<scenario>.csv untuk tahap ML.
// ---------------------------------------------------------------------------
class ReceiverApp : public Application
{
public:
  struct Stats
  {
    uint64_t rxTotal       = 0;  // semua paket yang masuk
    uint64_t rxLegitUnique = 0;  // paket dari sender resmi, bukan duplikat
    uint64_t rxLegitBytes  = 0;  // byte payload legit (untuk throughput)
    uint64_t duplicates    = 0;
    uint64_t spoofs        = 0;
    uint64_t unauthorized  = 0;
    double   sumDelayMs    = 0;  // akumulasi delay paket legit
    Time     lastLegitRx   = Seconds (0);
  };

  void
  Setup (uint16_t port, std::ofstream *csv)
  {
    m_port = port;
    m_csv  = csv;
  }

  const Stats &GetStats () const { return m_stats; }

private:
  void
  StartApplication () override
  {
    // 4a. Buat socket UDP dan bind ke 0.0.0.0:9000 agar menerima broadcast
    m_socket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_socket->Bind (InetSocketAddress (Ipv4Address::GetAny (), m_port));
    // 4b. Daftarkan callback: setiap ada paket masuk -> HandleRead()
    m_socket->SetRecvCallback (MakeCallback (&ReceiverApp::HandleRead, this));
  }

  void
  StopApplication () override
  {
    if (m_socket)
      {
        m_socket->Close ();
        m_socket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket>> ());
      }
  }

  void
  HandleRead (Ptr<Socket> socket)
  {
    Address     from;
    Ptr<Packet> pkt;
    while ((pkt = socket->RecvFrom (from)))
      {
        // 4c. Abaikan paket yang terlalu kecil untuk memuat AppTag
        AppTag tag;
        if (pkt->GetSize () < tag.GetSerializedSize ())
          {
            continue;
          }
        pkt->RemoveHeader (tag);

        // 4d. Identitas sebenarnya (dari IP header) vs identitas yang DIKLAIM (dari AppTag)
        Ipv4Address srcIp      = InetSocketAddress::ConvertFrom (from).GetIpv4 ();
        uint32_t    actualNode = NodeIdFromIp (srcIp);
        uint32_t    claimedSrc = tag.GetSrcId ();
        Time        now        = Simulator::Now ();
        double      delayMs    = (now - tag.GetTxTime ()).GetSeconds () * 1000.0;

        // 4e. Hitung fitur keamanan
        bool isDup   = !m_seen.insert (std::make_pair (claimedSrc, tag.GetSeq ())).second;
        bool isSpoof = (claimedSrc != actualNode);
        bool isUnauth = (actualNode != kSenderNodeId);

        // 4f. Update statistik ringkasan
        m_stats.rxTotal++;
        if (isDup)    m_stats.duplicates++;
        if (isSpoof)  m_stats.spoofs++;
        if (isUnauth) m_stats.unauthorized++;
        if (!isUnauth && !isDup)
          {
            m_stats.rxLegitUnique++;
            m_stats.rxLegitBytes += pkt->GetSize ();
            m_stats.sumDelayMs   += delayMs;
            m_stats.lastLegitRx   = now;
          }

        // 4g. Tulis satu baris CSV per paket (dataset untuk Phase 2: ML Risk)
        if (m_csv && m_csv->is_open ())
          {
            (*m_csv) << std::fixed << std::setprecision (6) << now.GetSeconds () << ","
                     << GetNode ()->GetId () << "," << tag.GetSeq () << "," << claimedSrc
                     << "," << srcIp << "," << actualNode << "," << pkt->GetSize () << ","
                     << std::setprecision (3) << delayMs << "," << (isDup ? 1 : 0) << ","
                     << (isSpoof ? 1 : 0) << "," << (isUnauth ? 1 : 0) << "\n";
          }
      }
  }

  Ptr<Socket>                                m_socket;
  uint16_t                                   m_port = kUdpPort;
  std::ofstream                             *m_csv  = nullptr;
  std::set<std::pair<uint32_t, uint32_t>>    m_seen; // (claimed_src, seq) yang sudah terlihat
  Stats                                      m_stats;
};

// ---------------------------------------------------------------------------
// STEP 5. AttackerApp (Node 5) - generator traffic serangan
//
// Perilaku bergantung pada --scenario:
//   FLOODING : kirim paket baru dengan rate tinggi (--attackRate), srcId = 5 (jujur,
//              tetapi volume besar) -> menaikkan packet rate, loss, delay.
//   REPLAY   : attacker "menyadap" broadcast LAN (bind port 9000), menyimpan salinan
//              paket legit, lalu mengirim ulang paket tsb apa adanya (seq & srcId=0
//              tetap) -> receiver melihat DUPLICATE dan delay yang janggal.
//   SPOOFING : kirim paket baru dengan srcId = 0 (mengaku sender) tetapi seq acak
//              karena tidak tahu seq yang valid -> receiver melihat SPOOF/auth failure.
// Serangan aktif hanya pada rentang [--attackStart, --attackStop].
// ---------------------------------------------------------------------------
class AttackerApp : public Application
{
public:
  void
  Setup (Scenario sc, Address dest, uint32_t payloadBytes, double rateMbps,
         Time attackStart, Time attackStop)
  {
    m_scenario    = sc;
    m_dest        = dest;
    m_payload     = payloadBytes;
    m_rateMbps    = rateMbps;
    m_attackStart = attackStart;
    m_attackStop  = attackStop;
    m_rng         = CreateObject<UniformRandomVariable> ();
  }

  uint32_t GetSentCount () const { return m_sent; }
  uint32_t GetCapturedCount () const { return m_capturedTotal; }

private:
  void
  StartApplication () override
  {
    // 5a. Socket pengirim (boleh broadcast)
    m_sendSocket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
    m_sendSocket->Bind ();
    m_sendSocket->SetAllowBroadcast (true);

    // 5b. Untuk REPLAY: buka socket penyadap di port 9000 sejak awal simulasi
    //     agar sudah ada "stok" paket legit saat serangan dimulai.
    if (m_scenario == Scenario::REPLAY)
      {
        m_sniffSocket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId ());
        m_sniffSocket->Bind (InetSocketAddress (Ipv4Address::GetAny (), kUdpPort));
        m_sniffSocket->SetRecvCallback (MakeCallback (&AttackerApp::Sniff, this));
      }

    // 5c. Jadwalkan mulai & berhenti serangan (relatif terhadap waktu sekarang)
    Time now = Simulator::Now ();
    Simulator::Schedule (m_attackStart > now ? m_attackStart - now : Seconds (0),
                         &AttackerApp::BeginAttack, this);
    Simulator::Schedule (m_attackStop > now ? m_attackStop - now : Seconds (0),
                         &AttackerApp::EndAttack, this);
  }

  void
  StopApplication () override
  {
    EndAttack ();
    if (m_sendSocket)  m_sendSocket->Close ();
    if (m_sniffSocket) m_sniffSocket->Close ();
  }

  // 5d. Callback penyadap: simpan salinan paket legit (maks 256 terakhir)
  void
  Sniff (Ptr<Socket> socket)
  {
    Address     from;
    Ptr<Packet> pkt;
    while ((pkt = socket->RecvFrom (from)))
      {
        m_captured.push_back (pkt->Copy ());
        m_capturedTotal++;
        if (m_captured.size () > 256)
          {
            m_captured.pop_front ();
          }
      }
  }

  void
  BeginAttack ()
  {
    if (m_attacking)
      {
        return;
      }
    m_attacking = true;
    NS_LOG_INFO ("[" << Simulator::Now ().GetSeconds () << "s] ATTACK START");
    std::cout << "[" << Simulator::Now ().GetSeconds () << "s] >>> Attacker (node "
              << GetNode ()->GetId () << ") mulai menyerang" << std::endl;
    SendAttackPacket ();
  }

  void
  EndAttack ()
  {
    if (!m_attacking)
      {
        return;
      }
    m_attacking = false;
    Simulator::Cancel (m_sendEvent);
    std::cout << "[" << Simulator::Now ().GetSeconds () << "s] <<< Attacker berhenti ("
              << m_sent << " paket serangan terkirim)" << std::endl;
  }

  // 5e. Kirim satu paket serangan sesuai skenario, lalu jadwalkan berikutnya
  void
  SendAttackPacket ()
  {
    if (!m_attacking)
      {
        return;
      }

    Ptr<Packet> pkt;
    switch (m_scenario)
      {
      case Scenario::FLOODING:
        {
          // Paket baru, identitas jujur (5), volume tinggi
          pkt = Create<Packet> (m_payload);
          AppTag tag;
          tag.SetSeq (++m_ownSeq);
          tag.SetSrcId (kAttackerNodeId);
          tag.SetTxTime (Simulator::Now ());
          pkt->AddHeader (tag);
          break;
        }
      case Scenario::REPLAY:
        {
          // 5f. Kirim ulang paket legit yang disadap apa adanya (seq & srcId=0 tetap).
          //     Jika belum ada yang disadap, lewati siklus ini.
          if (m_captured.empty ())
            {
              ScheduleNext ();
              return;
            }
          pkt = m_captured.front ().Copy ();
          m_captured.pop_front ();
          break;
        }
      case Scenario::SPOOFING:
        {
          // 5g. Paket baru, mengaku sebagai sender (srcId=0) tetapi seq acak
          //     -> receiver melihat SPOOF (claimed_src != actual_src) dan
          //        kemungkinan DUPLICATE (seq nabrakh dengan seq legit).
          pkt = Create<Packet> (m_payload);
          AppTag tag;
          tag.SetSeq (static_cast<uint32_t> (m_rng->GetInteger (1, 100000)));
          tag.SetSrcId (kSenderNodeId); // identitas palsu
          tag.SetTxTime (Simulator::Now ());
          pkt->AddHeader (tag);
          break;
        }
      default:
        {
          return; // Scenario::NORMAL -> tidak ada serangan
        }
    }

    m_sendSocket->SendTo (pkt, 0, m_dest);
    m_sent++;
    ScheduleNext ();
  }

  // 5h. Jadwalkan paket serangan berikutnya berdasarkan --attackRate
  void
  ScheduleNext ()
  {
    if (!m_attacking)
      {
        return;
      }
    double intervalSec = (m_payload * 8.0) / (m_rateMbps * 1e6);
    m_sendEvent = Simulator::Schedule (Seconds (intervalSec), &AttackerApp::SendAttackPacket, this);
  }

  Scenario              m_scenario    = Scenario::NORMAL;
  Address               m_dest;
  uint32_t              m_payload     = 400;
  double                m_rateMbps    = 20.0;
  Time                  m_attackStart = Seconds (2);
  Time                  m_attackStop  = Seconds (0);
  Ptr<Socket>           m_sendSocket;
  Ptr<Socket>           m_sniffSocket;
  bool                  m_attacking     = false;
  EventId              m_sendEvent;
  uint32_t              m_sent          = 0;
  uint32_t              m_ownSeq        = 100000;
  uint32_t              m_capturedTotal = 0;
  Ptr<UniformRandomVariable> m_rng;
  std::deque<Ptr<Packet>> m_captured;
};

// ---------------------------------------------------------------------------
// STEP 6. main()
// ---------------------------------------------------------------------------
int
main (int argc, char *argv[])
{
  // 6a. Parameter baris perintah (sesuai Experimental Matrix pada laporan)
  std::string scenarioStr = "normal";
  uint32_t    payload     = 800;
  double      legitRate   = 5.0;
  double      attackRate  = 20.0;
  double      simTime     = 20.0;
  double      attackStart = 2.0;
  double      attackStop  = 0.0;
  uint64_t    seed        = 1;
  bool        enableAnim  = true;
  bool        verbose     = true;
  std::string outPrefix   = "adaptive-security";

  CommandLine cmd (__FILE__);
  cmd.AddValue ("scenario", "normal | flooding | replay | spoofing", scenarioStr);
  cmd.AddValue ("payload", "ukuran payload (byte): 400/800/1200", payload);
  cmd.AddValue ("legitRate", "rate traffic legitimate (Mbps)", legitRate);
  cmd.AddValue ("attackRate", "rate traffic serangan (Mbps)", attackRate);
  cmd.AddValue ("simTime", "durasi simulasi (detik)", simTime);
  cmd.AddValue ("attackStart", "waktu mulai serangan (detik)", attackStart);
  cmd.AddValue ("attackStop", "waktu berhenti serangan, 0=sampai akhir", attackStop);
  cmd.AddValue ("seed", "seed RNG", seed);
  cmd.AddValue ("enableAnim", "hasilkan file XML NetAnim (1/0)", enableAnim);
  cmd.AddValue ("verbose", "cetak log progres (1/0)", verbose);
  cmd.AddValue ("outPrefix", "prefix nama file output", outPrefix);
  cmd.Parse (argc, argv);

  // 6b. Validasi skenario
  Scenario scenario;
  if (!ParseScenario (scenarioStr, scenario))
    {
      std::cerr << "Skenario tidak dikenal: " << scenarioStr << "\n"
                << "Pilih: normal | flooding | replay | spoofing\n";
      return 1;
    }
  if (attackStop <= 0.0)
    {
      attackStop = simTime;
    }

  // 6c. Seed RNG agar reproducible & bervariasi antar seed
  RngSeedManager::SetSeed (static_cast<uint32_t> (seed));
  RngSeedManager::SetRun (1);

  if (verbose)
    {
      LogComponentEnable ("AdaptiveSecuritySim", LOG_LEVEL_INFO);
    }

  std::cout << "========================================================\n"
            << " Adaptive Security Simulation - NS-3\n"
            << " Scenario    : " << scenarioStr << "\n"
            << " Payload     : " << payload << " byte\n"
            << " Legit rate  : " << legitRate << " Mbps\n"
            << " Attack rate : " << attackRate << " Mbps\n"
            << " Sim time    : " << simTime << " s\n"
            << " Attack win  : " << attackStart << " - " << attackStop << " s\n"
            << " Seed        : " << seed << "\n"
            << "========================================================\n";

  // 6d. Buat 6 node: 1 sender + 4 receiver + 1 attacker
  NodeContainer nodes;
  nodes.Create (kTotalNodes);

  // 6e. Pasang internet stack (IP, UDP, ...) ke semua node
  InternetStackHelper stack;
  stack.Install (nodes);

  // 6f. Link CSMA (LAN 100 Mbps) menghubungkan semua node
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", DataRateValue (DataRate (100000000)));
  csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));
  NetDeviceContainer devices = csma.Install (nodes);

  // 6g. Alamat IP 10.1.1.1 .. 10.1.1.6 (node k -> 10.1.1.(k+1))
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

  // 6h. Alamat broadcast subnet = 10.1.1.255
  Ipv4Address broadcastAddr = interfaces.GetAddress (0).GetBroadcast ();
  Address      bcastAddr     = InetSocketAddress (broadcastAddr, kUdpPort);

  // 6i. Posisi node untuk NetAnim
  MobilityHelper mobility;
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator",
                                 "MinX", DoubleValue (0.0), "MinY", DoubleValue (0.0),
                                 "DeltaX", DoubleValue (100.0), "DeltaY", DoubleValue (80.0),
                                 "GridWidth", UintegerValue (3), "LayoutType",
                                 StringValue ("RowFirst"));
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (nodes);

  // 6j. Buka file CSV security (header)
  std::ostringstream secFile;
  secFile << "security-" << scenarioStr << ".csv";
  std::ofstream secCsv (secFile.str ());
  secCsv << "time,rx_node,seq,claimed_src,actual_src_ip,actual_src_node,"
            "payload_size,delay_ms,is_duplicate,is_spoof,is_unauthorized\n";

  // 6k. Instal aplikasi
  //     Sender (node 0): broadcast UDP ke 10.1.1.255:9000
  Ptr<SenderApp> sender = CreateObject<SenderApp> ();
  sender->Setup (bcastAddr, payload, legitRate);
  nodes.Get (kSenderNodeId)->AddApplication (sender);
  sender->SetStartTime (Seconds (0.5));
  sender->SetStopTime (Seconds (simTime));

  //     Receiver (node 1-4): bind port 9000, catat ke CSV
  std::vector<Ptr<ReceiverApp>> receivers (kNumReceivers);
  for (uint32_t i = 0; i < kNumReceivers; ++i)
    {
      Ptr<ReceiverApp> rx = CreateObject<ReceiverApp> ();
      rx->Setup (kUdpPort, &secCsv);
      nodes.Get (kFirstRxNodeId + i)->AddApplication (rx);
      rx->SetStartTime (Seconds (0.4));
      rx->SetStopTime (Seconds (simTime));
      receivers[i] = rx;
    }

  //     Attacker (node 5): hanya jika skenario bukan normal
  Ptr<AttackerApp> attacker;
  if (scenario != Scenario::NORMAL)
    {
      attacker = CreateObject<AttackerApp> ();
      attacker->Setup (scenario, bcastAddr, payload, attackRate, Seconds (attackStart),
                       Seconds (attackStop));
      nodes.Get (kAttackerNodeId)->AddApplication (attacker);
      attacker->SetStartTime (Seconds (0.3)); // mulai menyadap lebih awal untuk REPLAY
      attacker->SetStopTime (Seconds (simTime));
    }

  // 6l. FlowMonitor (catatan: untuk broadcast, FlowMonitor hanya menghitung
  //     reception pertama per paket -> dipakai sebagai pelengkap statistik
  //     dari ReceiverApp).
  FlowMonitorHelper flowmon;
  Ptr<FlowMonitor> monitor = flowmon.InstallAll ();

  // 6m. AnimationInterface untuk NetAnim
  AnimationInterface *anim = nullptr;
  if (enableAnim)
    {
      std::ostringstream animFile;
      animFile << outPrefix << "-" << scenarioStr << "-anim.xml";
      anim = new AnimationInterface (animFile.str ());
      anim->SetMobilityPollInterval (Seconds (0.25));
      anim->EnablePacketMetadata (true);
      // Warna & label node agar mudah dibedakan di NetAnim
      anim->UpdateNodeDescription (kSenderNodeId, "SENDER");
      anim->UpdateNodeColor (kSenderNodeId, 0, 200, 0); // hijau
      anim->UpdateNodeSize (kSenderNodeId, 20, 20);
      for (uint32_t i = 0; i < kNumReceivers; ++i)
        {
          uint32_t id = kFirstRxNodeId + i;
          std::ostringstream nm; nm << "RX" << (i + 1);
          anim->UpdateNodeDescription (id, nm.str ());
          anim->UpdateNodeColor (id, 0, 100, 255); // biru
          anim->UpdateNodeSize (id, 15, 15);
        }
      anim->UpdateNodeDescription (kAttackerNodeId, "ATTACKER");
      anim->UpdateNodeColor (kAttackerNodeId, 255, 0, 0); // merah
      anim->UpdateNodeSize (kAttackerNodeId, 20, 20);
    }

  // 6n. Jalankan simulasi
  Simulator::Stop (Seconds (simTime));
  Simulator::Run ();

  // =====================================================================
  // STEP 7. Kumpulkan & tulis hasil setelah simulasi selesai
  // =====================================================================

  // 7a. Statistik FlowMonitor -> flowmon-<scenario>.csv + .xml
  monitor->CheckForLostPackets ();
  Ptr<Ipv4FlowClassifier> classifier =
      DynamicCast<Ipv4FlowClassifier> (flowmon.GetClassifier ());
  std::ostringstream fmCsvFile;
  fmCsvFile << "flowmon-" << scenarioStr << ".csv";
  std::ofstream fmCsv (fmCsvFile.str ());
  fmCsv << "flow_id,src_ip,dst_ip,src_port,dst_port,tx_packets,tx_bytes,"
           "rx_packets,rx_bytes,lost_packets,throughput_kbps,mean_delay_ms,"
           "pdr,loss_ratio\n";
  std::map<FlowId, FlowMonitor::FlowStats> fstats = monitor->GetFlowStats ();
  for (auto &kv : fstats)
    {
      auto         fs = kv.second;
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (kv.first);
      double       tpKbps = fs.timeLastRxPacket > fs.timeFirstTxPacket
                            ? (fs.rxBytes * 8.0) / 1000.0 /
                                  (fs.timeLastRxPacket - fs.timeFirstTxPacket).GetSeconds ()
                            : 0.0;
      double       meanDelayMs = fs.rxPackets > 0
                                    ? (fs.delaySum.GetSeconds () * 1000.0) / fs.rxPackets
                                    : 0.0;
      double       pdr       = fs.txPackets > 0 ? double (fs.rxPackets) / fs.txPackets : 0.0;
      double       lossRatio = fs.txPackets > 0 ? double (fs.lostPackets) / fs.txPackets : 0.0;
      fmCsv << kv.first << "," << t.sourceAddress << "," << t.destinationAddress << ","
            << t.sourcePort << "," << t.destinationPort << "," << fs.txPackets << ","
            << fs.txBytes << "," << fs.rxPackets << "," << fs.rxBytes << "," << fs.lostPackets
            << "," << std::fixed << std::setprecision (3) << tpKbps << "," << meanDelayMs << ","
            << std::setprecision (4) << pdr << "," << lossRatio << "\n";
    }
  fmCsv.close ();
  std::ostringstream fmXmlFile;
  fmXmlFile << "flowmon-" << scenarioStr << ".xml";
  monitor->SerializeToXmlFile (fmXmlFile.str (), true, true);

  // 7b. Tutup CSV security
  secCsv.close ();

  // 7c. Ringkasan per receiver -> summary-<scenario>.csv + cetak ke konsol
  std::ostringstream sumFile;
  sumFile << "summary-" << scenarioStr << ".csv";
  std::ofstream sumCsv (sumFile.str ());
  sumCsv << "scenario,rx_node,rx_total,rx_legit_unique,rx_legit_bytes,throughput_kbps,"
            "mean_delay_ms,duplicates,spoofs,unauthorized,duplicate_ratio,completion_time_s\n";

  std::cout << "\n================ RINGKASAN HASIL ================\n";
  std::cout << "Sender  (node 0) mengirim " << sender->GetSentCount () << " paket legit\n";
  if (attacker)
    {
      std::cout << "Attacker(node 5) mengirim " << attacker->GetSentCount ()
                << " paket serangan"
                << (scenario == Scenario::REPLAY
                        ? (std::string (" (dari ") +
                           std::to_string (attacker->GetCapturedCount ()) + " paket disadap)")
                        : std::string (""))
                << "\n";
    }
  std::cout << "------------------------------------------------\n";
  std::cout << "RX node | rxTotal | legitUniq | dup | spoof | unauth | thrput(kbps) | delay(ms)\n";

  for (uint32_t i = 0; i < kNumReceivers; ++i)
    {
      const auto &s = receivers[i]->GetStats ();
      uint32_t    nodeId = kFirstRxNodeId + i;
      double      dur = (s.rxLegitUnique > 0)
                            ? (s.lastLegitRx - Seconds (0.5)).GetSeconds ()
                            : 0.0;
      double      thrputKbps = dur > 0 ? (s.rxLegitBytes * 8.0) / 1000.0 / dur : 0.0;
      double      meanDelayMs = s.rxLegitUnique > 0 ? s.sumDelayMs / s.rxLegitUnique : 0.0;
      double      dupRatio = s.rxTotal > 0 ? double (s.duplicates) / s.rxTotal : 0.0;

      sumCsv << scenarioStr << "," << nodeId << "," << s.rxTotal << "," << s.rxLegitUnique
             << "," << s.rxLegitBytes << "," << std::fixed << std::setprecision (3)
             << thrputKbps << "," << std::setprecision (3) << meanDelayMs << ","
             << s.duplicates << "," << s.spoofs << "," << s.unauthorized << ","
             << std::setprecision (4) << dupRatio << "," << std::setprecision (3)
             << dur << "\n";

      std::cout << "  " << std::left << std::setw (7) << nodeId << " | " << std::right
                << std::setw (7) << s.rxTotal << " | " << std::setw (9) << s.rxLegitUnique
                << " | " << std::setw (3) << s.duplicates << " | " << std::setw (5)
                << s.spoofs << " | " << std::setw (6) << s.unauthorized << " | "
                << std::setw (11) << std::setprecision (2) << thrputKbps << " | "
                << std::setw (8) << meanDelayMs << "\n";
    }
  sumCsv.close ();
  std::cout << "==================================================\n";
  std::cout << "File output:\n"
            << "  - " << outPrefix << "-" << scenarioStr << "-anim.xml (NetAnim)\n"
            << "  - security-" << scenarioStr << ".csv\n"
            << "  - flowmon-" << scenarioStr << ".csv / .xml\n"
            << "  - summary-" << scenarioStr << ".csv\n";

  // 7d. Cleanup
  if (anim)
    {
      delete anim;
    }
  Simulator::Destroy ();
  return 0;
}