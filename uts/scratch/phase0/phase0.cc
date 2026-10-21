/*
 * Fase 0: topologi bintang + trafik normal.
 *
 * Tujuh node: pengirim (0), penerima (1-4), penyerang yang diam (5), switch (6).
 * Setiap node 0-5 punya kabel CSMA sendiri ke switch. Bukan satu kabel bersama.
 *
 * Fase 1 nanti menambah kelas AttackerApp sendiri.
 * Jangan mengubah DisseminationSender atau DisseminationReceiver untuk itu.
 * Fungsi ComputeAuthTag() sengaja diletakkan di luar kedua kelas supaya
 * AttackerApp bisa memakai cap yang sama.
 *
 * NetAnim (kartun paket) hanya dibuat jika --anim=1.
 * Modul netanim adalah tambahan yang diminta; matriks 45 run memakai --anim=0.
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/bridge-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"

#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <cerrno>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Phase0Dissemination");

namespace {

// Rahasia bersama. Ini bukan kriptografi sungguhan.
// Nanti dipakai untuk menghitung paket yang cap-nya gagal atau identitasnya palsu.
const uint32_t kSecret = 0x5EC0DE01u;

// FNV-1a 32-bit. Urutan byte dibuat big-endian supaya hasilnya sama
// di machina mana pun, tidak bergantung pada endian mesin.
uint32_t
Fnv1a32(const uint8_t* data, size_t length)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < length; ++i)
    {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

void
AppendBe32(std::vector<uint8_t>& bytes, uint32_t value)
{
    bytes.push_back(static_cast<uint8_t>((value >> 24) & 0xffu));
    bytes.push_back(static_cast<uint8_t>((value >> 16) & 0xffu));
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
    bytes.push_back(static_cast<uint8_t>(value & 0xffu));
}

void
AppendBe16(std::vector<uint8_t>& bytes, uint16_t value)
{
    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
    bytes.push_back(static_cast<uint8_t>(value & 0xffu));
}

// Cap = fnv1a32(seq | claimedId | SECRET)
uint32_t
ComputeAuthTag(uint32_t seq, uint16_t claimedId)
{
    std::vector<uint8_t> bytes;
    bytes.reserve(10);
    AppendBe32(bytes, seq);
    AppendBe16(bytes, claimedId);
    AppendBe32(bytes, kSecret);
    return Fnv1a32(bytes.data(), bytes.size());
}

// mkdir satu tingkat demi satu tingkat. Tidak memakai std::filesystem
// supaya tetap jalan di NS-3 yang masih memakai C++11/14.
void
EnsureDirectory(const std::string& path)
{
    std::string current;
    current.reserve(path.size());
    for (size_t i = 0; i < path.size(); ++i)
    {
        current.push_back(path[i]);
        if (path[i] == '/' || i + 1 == path.size())
        {
            if (current.empty() || current == "." || current == "/")
            {
                continue;
            }
            if (mkdir(current.c_str(), 0755) != 0 && errno != EEXIST)
            {
                NS_FATAL_ERROR("Tidak bisa membuat folder " << current);
            }
        }
    }
}

std::string
MakeRunId(const std::string& tag, uint32_t payload, double rateMbps, uint32_t seed)
{
    std::ostringstream id;
    id << tag << "_p" << payload << "_r";
    if (std::floor(rateMbps) == rateMbps)
    {
        id << static_cast<unsigned>(rateMbps);
    }
    else
    {
        id << rateMbps;
    }
    id << "_s" << seed;
    return id.str();
}

} // namespace

// Kepala paket di dalam payload UDP.
// Ukuran tetap 18 byte. Sisa payload diisi byte kosong supaya
// total payload UDP = --payload (400, 800, atau 1200).
class DissHeader : public Header
{
  public:
    DissHeader();

    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;

    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    void SetSeq(uint32_t seq);
    void SetTxTimeNs(uint64_t txTimeNs);
    void SetClaimedId(uint16_t claimedId);
    void SetAuthTag(uint32_t authTag);

    uint32_t GetSeq() const;
    uint64_t GetTxTimeNs() const;
    uint16_t GetClaimedId() const;
    uint32_t GetAuthTag() const;

  private:
    uint32_t m_seq;
    uint64_t m_txTimeNs;
    uint16_t m_claimedId;
    uint32_t m_authTag;
};

NS_OBJECT_ENSURE_REGISTERED(DissHeader);

DissHeader::DissHeader()
    : m_seq(0),
      m_txTimeNs(0),
      m_claimedId(0),
      m_authTag(0)
{
}

TypeId
DissHeader::GetTypeId()
{
    static TypeId tid = TypeId("DissHeader")
                            .SetParent<Header>()
                            .SetGroupName("Applications")
                            .AddConstructor<DissHeader>();
    return tid;
}

TypeId
DissHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
DissHeader::GetSerializedSize() const
{
    // 4 + 8 + 2 + 4. Timestamp ditulis sebagai dua uint32
    // karena WriteHtonU64 tidak ada di semua versi NS-3.
    return 18;
}

void
DissHeader::Serialize(Buffer::Iterator start) const
{
    start.WriteHtonU32(m_seq);
    start.WriteHtonU32(static_cast<uint32_t>(m_txTimeNs >> 32));
    start.WriteHtonU32(static_cast<uint32_t>(m_txTimeNs & 0xffffffffu));
    start.WriteHtonU16(m_claimedId);
    start.WriteHtonU32(m_authTag);
}

uint32_t
DissHeader::Deserialize(Buffer::Iterator start)
{
    m_seq = start.ReadNtohU32();
    uint32_t hi = start.ReadNtohU32();
    uint32_t lo = start.ReadNtohU32();
    m_txTimeNs = (static_cast<uint64_t>(hi) << 32) | lo;
    m_claimedId = start.ReadNtohU16();
    m_authTag = start.ReadNtohU32();
    return GetSerializedSize();
}

void
DissHeader::Print(std::ostream& os) const
{
    os << "seq=" << m_seq << " txTimeNs=" << m_txTimeNs << " claimedId=" << m_claimedId
       << " authTag=" << m_authTag;
}

void
DissHeader::SetSeq(uint32_t seq)
{
    m_seq = seq;
}

void
DissHeader::SetTxTimeNs(uint64_t txTimeNs)
{
    m_txTimeNs = txTimeNs;
}

void
DissHeader::SetClaimedId(uint16_t claimedId)
{
    m_claimedId = claimedId;
}

void
DissHeader::SetAuthTag(uint32_t authTag)
{
    m_authTag = authTag;
}

uint32_t
DissHeader::GetSeq() const
{
    return m_seq;
}

uint64_t
DissHeader::GetTxTimeNs() const
{
    return m_txTimeNs;
}

uint16_t
DissHeader::GetClaimedId() const
{
    return m_claimedId;
}

uint32_t
DissHeader::GetAuthTag() const
{
    return m_authTag;
}

// Node 0. Mengirim UDP broadcast ke 10.1.1.255:9000.
class DisseminationSender : public Application
{
  public:
    static TypeId GetTypeId();

    DisseminationSender();
    ~DisseminationSender() override;

    void Setup(uint32_t payloadBytes,
               double rateMbps,
               std::string runId,
               std::ofstream* txFile);

    uint32_t GetPacketsSent() const;

  private:
    void StartApplication() override;
    void StopApplication() override;
    void DoDispose() override;
    void SendPacket();

    uint32_t m_payloadBytes;
    double m_rateBps;
    std::string m_runId;
    std::ofstream* m_txFile;
    Ptr<Socket> m_socket;
    Ptr<UniformRandomVariable> m_jitter;
    EventId m_sendEvent;
    uint32_t m_seq;
    uint32_t m_sent;
    bool m_running;
};

NS_OBJECT_ENSURE_REGISTERED(DisseminationSender);

TypeId
DisseminationSender::GetTypeId()
{
    static TypeId tid = TypeId("DisseminationSender")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<DisseminationSender>();
    return tid;
}

DisseminationSender::DisseminationSender()
    : m_payloadBytes(800),
      m_rateBps(5e6),
      m_txFile(nullptr),
      m_seq(0),
      m_sent(0),
      m_running(false)
{
}

DisseminationSender::~DisseminationSender()
{
}

void
DisseminationSender::Setup(uint32_t payloadBytes,
                           double rateMbps,
                           std::string runId,
                           std::ofstream* txFile)
{
    m_payloadBytes = payloadBytes;
    m_rateBps = rateMbps * 1e6;
    m_runId = runId;
    m_txFile = txFile;
}

uint32_t
DisseminationSender::GetPacketsSent() const
{
    return m_sent;
}

void
DisseminationSender::StartApplication()
{
    m_running = true;

    // Stream nomor 10 dipatok setelah seed di-set di main().
    // Tanpa SetStream, nomor stream bisa bergeser antar versi NS-3
    // dan jejak waktu tidak lagi sama untuk seed yang sama.
    m_jitter = CreateObject<UniformRandomVariable>();
    m_jitter->SetAttribute("Min", DoubleValue(0.9));
    m_jitter->SetAttribute("Max", DoubleValue(1.1));
    m_jitter->SetStream(10);

    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9000));
    m_socket->SetAllowBroadcast(true);

    SendPacket();
}

void
DisseminationSender::StopApplication()
{
    m_running = false;
    if (m_sendEvent.IsPending())
    {
        Simulator::Cancel(m_sendEvent);
    }
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
DisseminationSender::DoDispose()
{
    m_socket = nullptr;
    m_jitter = nullptr;
    Application::DoDispose();
}

void
DisseminationSender::SendPacket()
{
    if (!m_running)
    {
        return;
    }

    DissHeader header;
    uint64_t txTimeNs = static_cast<uint64_t>(Simulator::Now().GetNanoSeconds());
    header.SetSeq(m_seq);
    header.SetTxTimeNs(txTimeNs);
    header.SetClaimedId(0);
    header.SetAuthTag(ComputeAuthTag(m_seq, 0));

    // Sisa byte setelah kepala 18 byte adalah bantalan, bukan data rahasia.
    uint32_t pad = m_payloadBytes - header.GetSerializedSize();
    Ptr<Packet> packet = Create<Packet>(pad);
    packet->AddHeader(header);

    InetSocketAddress destination(Ipv4Address("10.1.1.255"), 9000);
    m_socket->SendTo(packet, 0, destination);

    double txTimeS = static_cast<double>(txTimeNs) / 1e9;
    if (m_txFile)
    {
        (*m_txFile) << m_runId << ',' << m_seq << ",0," << m_payloadBytes << ',' << txTimeS
                    << '\n';
    }

    NS_LOG_INFO("kirim seq=" << m_seq << " pada " << txTimeS);
    m_sent += 1;
    m_seq += 1;

    // Jeda dasar = ukuran bit / laju yang diminta, lalu dikali angka acak 0.9-1.1.
    // Seed berbeda menghasilkan jeda berbeda.
    double factor = m_jitter->GetValue();
    double intervalS = (static_cast<double>(m_payloadBytes) * 8.0 / m_rateBps) * factor;
    Time next = Simulator::Now() + Seconds(intervalS);
    if (next < m_stopTime)
    {
        m_sendEvent = Simulator::Schedule(Seconds(intervalS), &DisseminationSender::SendPacket, this);
    }
}

// Node 1-4. Tidak dipasang di node 5.
class DisseminationReceiver : public Application
{
  public:
    static TypeId GetTypeId();

    DisseminationReceiver();
    ~DisseminationReceiver() override;

    void Setup(uint32_t nodeId, std::string runId, std::ofstream* rxFile);

  private:
    void StartApplication() override;
    void StopApplication() override;
    void DoDispose() override;
    void HandleRead(Ptr<Socket> socket);

    uint32_t m_nodeId;
    std::string m_runId;
    std::ofstream* m_rxFile;
    Ptr<Socket> m_socket;
    std::set<uint32_t> m_seen;
};

NS_OBJECT_ENSURE_REGISTERED(DisseminationReceiver);

TypeId
DisseminationReceiver::GetTypeId()
{
    static TypeId tid = TypeId("DisseminationReceiver")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<DisseminationReceiver>();
    return tid;
}

DisseminationReceiver::DisseminationReceiver()
    : m_nodeId(0),
      m_rxFile(nullptr)
{
}

DisseminationReceiver::~DisseminationReceiver()
{
}

void
DisseminationReceiver::Setup(uint32_t nodeId, std::string runId, std::ofstream* rxFile)
{
    m_nodeId = nodeId;
    m_runId = runId;
    m_rxFile = rxFile;
}

void
DisseminationReceiver::StartApplication()
{
    m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9000));
    m_socket->SetRecvCallback(MakeCallback(&DisseminationReceiver::HandleRead, this));
}

void
DisseminationReceiver::StopApplication()
{
    if (m_socket)
    {
        m_socket->Close();
    }
}

void
DisseminationReceiver::DoDispose()
{
    m_socket = nullptr;
    Application::DoDispose();
}

void
DisseminationReceiver::HandleRead(Ptr<Socket> socket)
{
    Ptr<Packet> packet;
    while ((packet = socket->Recv()))
    {
        DissHeader header;
        packet->RemoveHeader(header);

        uint32_t seq = header.GetSeq();
        uint16_t claimedId = header.GetClaimedId();
        uint32_t sizeBytes = header.GetSerializedSize() + packet->GetSize();
        uint64_t nowNs = static_cast<uint64_t>(Simulator::Now().GetNanoSeconds());
        double rxTimeS = static_cast<double>(nowNs) / 1e9;
        double txTimeS = static_cast<double>(header.GetTxTimeNs()) / 1e9;
        double delayS = rxTimeS - txTimeS;

        uint32_t expected = ComputeAuthTag(seq, claimedId);
        int authOk = (expected == header.GetAuthTag()) ? 1 : 0;

        int isDuplicate = 0;
        if (!m_seen.insert(seq).second)
        {
            isDuplicate = 1;
        }

        if (m_rxFile)
        {
            (*m_rxFile) << m_runId << ',' << m_nodeId << ',' << seq << ',' << claimedId << ','
                        << sizeBytes << ',' << txTimeS << ',' << rxTimeS << ',' << delayS << ','
                        << authOk << ',' << isDuplicate << '\n';
        }

        NS_LOG_INFO("node " << m_nodeId << " terima seq=" << seq);
    }
}

int
main(int argc, char* argv[])
{
    uint32_t payload = 800;
    double rateMbps = 5.0;
    std::string linkRate = "100Mbps";
    std::string linkDelay = "2us";
    double simTime = 60.0;
    double appStart = 2.0;
    uint32_t seed = 1;
    uint32_t runNumber = 1;
    std::string outDir = "out/phase0";
    std::string tag = "normal";
    uint32_t anim = 0;
    // NS-3 tidak punya satu fungsi versi yang stabil dari 3.25 sampai 3.45.
    // Skrip mengisi nilai ini dari `./ns3 --version` atau `./waf --version`.
    std::string ns3Version = "unrecorded";

    // NS-3 >= 3.36: constructor ini yang dipakai contoh resmi.
    // Kalau kompiler bilang tidak ada constructor CommandLine(const char*),
    // ganti baris berikut menjadi: CommandLine cmd;
    CommandLine cmd(__FILE__);
    cmd.AddValue("payload", "Ukuran payload UDP (byte). Matriks: 400, 800, 1200.", payload);
    cmd.AddValue("rateMbps", "Laju kirim yang diminta, dalam Mbps. Matriks: 2, 5, 10.", rateMbps);
    cmd.AddValue("linkRate", "DataRate kabel CSMA, misalnya 100Mbps.", linkRate);
    cmd.AddValue("linkDelay", "Delay kabel CSMA, misalnya 2us.", linkDelay);
    cmd.AddValue("simTime", "Lama simulasi (detik).", simTime);
    cmd.AddValue("appStart", "Detik mulai aplikasi.", appStart);
    cmd.AddValue("seed", "RngSeedManager seed.", seed);
    cmd.AddValue("run", "RngSeedManager run.", runNumber);
    cmd.AddValue("outDir", "Folder keluaran, path relatif.", outDir);
    cmd.AddValue("tag", "Label skenario. Fase 0: normal.", tag);
    cmd.AddValue("anim", "1 = tulis XML NetAnim, 0 = tidak.", anim);
    cmd.AddValue("ns3Version", "Teks versi NS-3 untuk meta.json.", ns3Version);
    cmd.Parse(argc, argv);

    if (payload < 18)
    {
        NS_FATAL_ERROR("payload minimal 18 byte karena kepala paket butuh 18 byte");
    }
    if (rateMbps <= 0.0)
    {
        NS_FATAL_ERROR("rateMbps harus lebih dari 0");
    }
    if (appStart < 0.0 || appStart >= simTime)
    {
        NS_FATAL_ERROR("appStart harus >= 0 dan lebih kecil dari simTime");
    }

    // Seed wajib di-set sebelum variabel acak pertama dibuat.
    RngSeedManager::SetSeed(seed);
    RngSeedManager::SetRun(runNumber);

    std::string runId = MakeRunId(tag, payload, rateMbps, seed);
    std::string runDir = outDir + "/" + runId;
    EnsureDirectory(runDir);

    std::ofstream txFile(runDir + "/packets_tx.csv", std::ios::out | std::ios::trunc);
    std::ofstream rxFile(runDir + "/packets_rx.csv", std::ios::out | std::ios::trunc);
    if (!txFile.is_open() || !rxFile.is_open())
    {
        NS_FATAL_ERROR("Tidak bisa membuka CSV di " << runDir);
    }
    txFile.setf(std::ios::fixed);
    rxFile.setf(std::ios::fixed);
    txFile << std::setprecision(9);
    rxFile << std::setprecision(9);
    txFile << "run_id,seq,claimed_id,size_bytes,tx_time_s\n";
    rxFile << "run_id,node_id,seq,claimed_id,size_bytes,tx_time_s,rx_time_s,delay_s,auth_ok,is_duplicate\n";

    // Node 0-5 ujung, node 6 switch. Create(7) mengunci nomor ini
    // selama simulasi tidak membuat node lain lebih dulu.
    NodeContainer nodes;
    nodes.Create(7);

    CsmaHelper csma;
    // String DataRate/Delay dilewatkan apa adanya supaya --linkRate dan --linkDelay
    // tetap bisa diubah tanpa mengompilasi ulang. Parser string ini ada sejak lama,
    // meski di versi baru ada peringatan deprecated.
    csma.SetChannelAttribute("DataRate", DataRateValue(DataRate(linkRate)));
    csma.SetChannelAttribute("Delay", TimeValue(Time(linkDelay)));
    csma.SetDeviceAttribute("Mtu", UintegerValue(1500));

    NetDeviceContainer terminalDevices;
    NetDeviceContainer switchPorts;
    for (uint32_t i = 0; i < 6; ++i)
    {
        // Satu Install = satu channel. Enam kali, jadi enam kabel ke switch.
        NodeContainer pair;
        pair.Add(nodes.Get(i));
        pair.Add(nodes.Get(6));
        NetDeviceContainer link = csma.Install(pair);
        terminalDevices.Add(link.Get(0));
        switchPorts.Add(link.Get(1));
    }

    BridgeHelper bridge;
    bridge.Install(nodes.Get(6), switchPorts);

    // Stack IP hanya di node 0-5. Switch tidak punya alamat IP.
    NodeContainer terminals;
    for (uint32_t i = 0; i < 6; ++i)
    {
        terminals.Add(nodes.Get(i));
    }
    InternetStackHelper internet;
    internet.Install(terminals);

    Ipv4AddressHelper ipv4;
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    ipv4.Assign(terminalDevices);

    Ptr<DisseminationSender> sender = CreateObject<DisseminationSender>();
    sender->Setup(payload, rateMbps, runId, &txFile);
    nodes.Get(0)->AddApplication(sender);
    sender->SetStartTime(Seconds(appStart));
    sender->SetStopTime(Seconds(simTime));

    for (uint32_t nodeId = 1; nodeId <= 4; ++nodeId)
    {
        Ptr<DisseminationReceiver> receiver = CreateObject<DisseminationReceiver>();
        receiver->Setup(nodeId, runId, &rxFile);
        nodes.Get(nodeId)->AddApplication(receiver);
        receiver->SetStartTime(Seconds(appStart));
        receiver->SetStopTime(Seconds(simTime));
    }
    // Node 5 (penyerang) punya IP dari Assign di atas, tetapi tidak menerima aplikasi.
    // Itu disengaja. Fase 1 memasang AttackerApp di node ini tanpa mengubah kelas di atas.

    // Pointer biasa, bukan objek di stack: destructor NetAnim menulis penutup XML.
    // Ia harus hidup selama Simulator::Run(), lalu dihapus sebelum Destroy().
    AnimationInterface* animator = nullptr;
    if (anim != 0)
    {
        // Pasang posisi diam sebelum AnimationInterface dibuat.
        // Constructor NetAnim memperingatkan setiap node yang belum punya MobilityModel,
        // dan SetConstantPosition mencetak peringatan yang sama lagi sebelum memasang model.
        const double cx = 50.0;
        const double cy = 50.0;
        const double radius = 40.0;
        const double pi = 3.141592653589793;
        MobilityHelper mobility;
        mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobility.Install(nodes);
        nodes.Get(6)->GetObject<MobilityModel>()->SetPosition(Vector(cx, cy, 0.0));
        for (uint32_t i = 0; i < 6; ++i)
        {
            double angle = -pi / 2.0 + (2.0 * pi * static_cast<double>(i) / 6.0);
            nodes.Get(i)->GetObject<MobilityModel>()->SetPosition(
                Vector(cx + radius * std::cos(angle), cy + radius * std::sin(angle), 0.0));
        }

        animator = new AnimationInterface(runDir + "/animation.xml");
        animator->SetMaxPktsPerTraceFile(500000);
        animator->EnablePacketMetadata(true);

        animator->SetConstantPosition(nodes.Get(6), cx, cy);
        animator->UpdateNodeDescription(nodes.Get(6), "Switch");
        animator->UpdateNodeColor(nodes.Get(6), 160, 160, 160);

        for (uint32_t i = 0; i < 6; ++i)
        {
            double angle = -pi / 2.0 + (2.0 * pi * static_cast<double>(i) / 6.0);
            animator->SetConstantPosition(nodes.Get(i),
                                          cx + radius * std::cos(angle),
                                          cy + radius * std::sin(angle));
        }
        animator->UpdateNodeDescription(nodes.Get(0), "Sender");
        animator->UpdateNodeColor(nodes.Get(0), 0, 180, 0);
        for (uint32_t i = 1; i <= 4; ++i)
        {
            std::ostringstream label;
            label << "Receiver " << i;
            animator->UpdateNodeDescription(nodes.Get(i), label.str());
            animator->UpdateNodeColor(nodes.Get(i), 30, 90, 200);
        }
        animator->UpdateNodeDescription(nodes.Get(5), "Attacker");
        animator->UpdateNodeColor(nodes.Get(5), 200, 40, 40);
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    uint32_t packetsSent = sender->GetPacketsSent();

    delete animator;
    animator = nullptr;

    txFile.close();
    rxFile.close();

    std::ofstream meta(runDir + "/meta.json", std::ios::out | std::ios::trunc);
    if (!meta.is_open())
    {
        NS_FATAL_ERROR("Tidak bisa menulis meta.json di " << runDir);
    }
    meta << "{\n"
         << "  \"run_id\": \"" << runId << "\",\n"
         << "  \"tag\": \"" << tag << "\",\n"
         << "  \"payload\": " << payload << ",\n"
         << "  \"rate_mbps\": " << rateMbps << ",\n"
         << "  \"link_rate\": \"" << linkRate << "\",\n"
         << "  \"link_delay\": \"" << linkDelay << "\",\n"
         << "  \"mtu\": 1500,\n"
         << "  \"sim_time_s\": " << simTime << ",\n"
         << "  \"app_start_s\": " << appStart << ",\n"
         << "  \"seed\": " << seed << ",\n"
         << "  \"run\": " << runNumber << ",\n"
         << "  \"ns3_version\": \"" << ns3Version << "\",\n"
         << "  \"packets_sent\": " << packetsSent << ",\n"
         << "  \"anim\": " << (anim ? "true" : "false") << ",\n"
         << "  \"port\": 9000,\n"
         << "  \"subnet\": \"10.1.1.0/24\",\n"
         << "  \"secret\": \"0x5EC0DE01\"\n"
         << "}\n";
    meta.close();

    Simulator::Destroy();
    return 0;
}
