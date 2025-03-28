# Wire1
Program 1

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TrafficControlExample");

int
main(int argc, char* argv[])
{
    double simulationTime = 10; // simulation time
    std::string transportProt = "Udp";//socket protocol
    std::string socketType;

   

    if (transportProt == "Tcp")
    {
        socketType = "ns3::TcpSocketFactory";
    }
    else
    {
        socketType = "ns3::UdpSocketFactory";
    }

    NodeContainer nodes;
    nodes.Create(5);//number of nodes

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("15Mbps"));//10,20,30 bandwidth change
    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));
    pointToPoint.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("10p"));

//node connectivity
    NetDeviceContainer devices01;
    devices01 = pointToPoint.Install(nodes.Get(0),nodes.Get(1));
   
    NetDeviceContainer devices02;
    devices02= pointToPoint.Install(nodes.Get(0),nodes.Get(2));
   
    NetDeviceContainer devices12;
    devices12= pointToPoint.Install(nodes.Get(1),nodes.Get(2));
   
    NetDeviceContainer devices23;
    devices23= pointToPoint.Install(nodes.Get(2),nodes.Get(3));
   
    NetDeviceContainer devices24;
    devices24= pointToPoint.Install(nodes.Get(2),nodes.Get(4));
   
    NetDeviceContainer devices34;
    devices34= pointToPoint.Install(nodes.Get(3),nodes.Get(4));
   
    InternetStackHelper stack;
    stack.Install(nodes);

//node interfaces and address allocation
    Ipv4AddressHelper address01;
    address01.SetBase("10.1.1.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces01= address01.Assign(devices01);


    Ipv4AddressHelper address02;
    address02.SetBase("10.1.2.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces02= address02.Assign(devices02);

    Ipv4AddressHelper address12;
    address12.SetBase("10.1.3.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces12= address12.Assign(devices12);

    Ipv4AddressHelper address23;
    address23.SetBase("10.1.4.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces23= address23.Assign(devices23);
   
     Ipv4AddressHelper address24;
    address24.SetBase("10.1.5.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces24= address24.Assign(devices24);
   
     Ipv4AddressHelper address34;
    address34.SetBase("10.1.6.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces34= address34.Assign(devices34);
   
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Flow
    uint16_t port = 7;
    Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
    PacketSinkHelper packetSinkHelper(socketType, localAddress);
    ApplicationContainer sinkApp = packetSinkHelper.Install(nodes.Get(4));// destination node

    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simulationTime + 0.1));

    uint32_t payloadSize = 1448;
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    OnOffHelper onoff(socketType, Ipv4Address::GetAny());
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
    onoff.SetAttribute("DataRate", StringValue("50Mbps")); // bit/s
    ApplicationContainer apps;

    InetSocketAddress rmt(interfaces34.GetAddress(1), port); // interface-destination, address-neighbour node
    onoff.SetAttribute("Remote", AddressValue(rmt));
    onoff.SetAttribute("Tos", UintegerValue(0xb8));
    apps.Add(onoff.Install(nodes.Get(0)));// sender
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(simulationTime + 0.1));

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simulationTime + 5));
    Simulator::Run();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    std::cout << std::endl << "*** Flow monitor statistics ***" << std::endl;
    std::cout << "  Tx Packets/Bytes:   " << stats[1].txPackets << " / " << stats[1].txBytes
              << std::endl;
    std::cout << "  Rx Packets/Bytes:   " << stats[1].rxPackets << " / " << stats[1].rxBytes
              << std::endl;
    std::cout << "  Packets/Bytes Dropped :   " <<stats[1].lostPackets  << std::endl;
    std::cout << "  Throughput: "
              << stats[1].rxBytes * 8.0 /
                     (stats[1].timeLastRxPacket.GetSeconds() -
                      stats[1].timeFirstRxPacket.GetSeconds()) /
                     1000000
              << " Mbps" << std::endl;
    std::cout << "  Mean delay:   " << stats[1].delaySum.GetSeconds() / stats[1].rxPackets
              << std::endl;
    std::cout << "  Mean jitter:   " << stats[1].jitterSum.GetSeconds() / (stats[1].rxPackets - 1)
              << std::endl;
    Simulator::Destroy();
    return 0;
}
Program 2

/*
 * Copyright (c) 2015 Universita' degli Studi di Napoli "Federico II"
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Pasquale Imputato <p.imputato@gmail.com>
 * Author: Stefano Avallone <stefano.avallone@unina.it>
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TrafficControlExample");



int
main(int argc, char* argv[])
{
    double simulationTime = 10; // seconds
    std::string transportProt = "Udp";
    std::string socketType;

   

    if (transportProt == "Tcp")
    {
        socketType = "ns3::TcpSocketFactory";
    }
    else
    {
        socketType = "ns3::UdpSocketFactory";
    }

    NodeContainer nodes;
    nodes.Create(5);

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("30Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));
    pointToPoint.SetQueue("ns3::DropTailQueue", "MaxSize", StringValue("10p"));

   
//node connectivity
    NetDeviceContainer devices01;
    devices01 = pointToPoint.Install(nodes.Get(0),nodes.Get(1));
   
    NetDeviceContainer devices02;
    devices02= pointToPoint.Install(nodes.Get(0),nodes.Get(2));
   
    NetDeviceContainer devices12;
    devices12= pointToPoint.Install(nodes.Get(1),nodes.Get(2));
   
    NetDeviceContainer devices23;
    devices23= pointToPoint.Install(nodes.Get(2),nodes.Get(3));
   
    NetDeviceContainer devices24;
    devices24= pointToPoint.Install(nodes.Get(2),nodes.Get(4));
   
    NetDeviceContainer devices34;
    devices34= pointToPoint.Install(nodes.Get(3),nodes.Get(4));
   
    InternetStackHelper stack;
    stack.Install(nodes);

//node interfaces and address allocation
    Ipv4AddressHelper address01;
    address01.SetBase("10.1.1.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces01= address01.Assign(devices01);


    Ipv4AddressHelper address02;
    address02.SetBase("10.1.2.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces02= address02.Assign(devices02);

    Ipv4AddressHelper address12;
    address12.SetBase("10.1.3.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces12= address12.Assign(devices12);

    Ipv4AddressHelper address23;
    address23.SetBase("10.1.4.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces23= address23.Assign(devices23);
   
     Ipv4AddressHelper address24;
    address24.SetBase("10.1.5.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces24= address24.Assign(devices24);
   
     Ipv4AddressHelper address34;
    address34.SetBase("10.1.6.0", "255.255.255.0");

    Ipv4InterfaceContainer interfaces34= address34.Assign(devices34);
   
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // UDP Flow
    uint16_t port = 7;
    Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
    PacketSinkHelper packetSinkHelper(socketType, localAddress);
    ApplicationContainer sinkApp = packetSinkHelper.Install(nodes.Get(4));// receiver

    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simulationTime + 0.1));

    uint32_t payloadSize = 1448;
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    OnOffHelper onoff(socketType, Ipv4Address::GetAny());
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
    onoff.SetAttribute("DataRate", StringValue("50Mbps")); // bit/s
    ApplicationContainer apps;

    InetSocketAddress rmt(interfaces34.GetAddress(1), port); //interface-destination, address-neighbour node
    onoff.SetAttribute("Remote", AddressValue(rmt));
    onoff.SetAttribute("Tos", UintegerValue(0xb8));
    apps.Add(onoff.Install(nodes.Get(0)));//sender
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(simulationTime + 0.1));


// TCP Flow
    uint16_t porttcp = 9;
    socketType = "ns3::TcpSocketFactory";
   
    Address localAddresstcp(InetSocketAddress(Ipv4Address::GetAny(), porttcp));
    PacketSinkHelper packetSinkHelpertcp(socketType, localAddresstcp);
    ApplicationContainer sinkApptcp = packetSinkHelpertcp.Install(nodes.Get(4));//reciever

    sinkApptcp.Start(Seconds(1.0));
    sinkApptcp.Stop(Seconds(simulationTime + 0.1));

   
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    OnOffHelper onofftcp(socketType, Ipv4Address::GetAny());
    onofftcp.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onofftcp.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onofftcp.SetAttribute("PacketSize", UintegerValue(payloadSize));
    onofftcp.SetAttribute("DataRate", StringValue("5Mbps")); // bit/s
    ApplicationContainer appstcp;

    InetSocketAddress rmttcp(interfaces34.GetAddress(1), porttcp);//interface-destination, address-neighbour node
    onofftcp.SetAttribute("Remote", AddressValue(rmttcp));
    onofftcp.SetAttribute("Tos", UintegerValue(0xb8));
    appstcp.Add(onofftcp.Install(nodes.Get(2)));//sender
    appstcp.Start(Seconds(1.5));
    appstcp.Stop(Seconds(simulationTime + 0.1));
   
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simulationTime + 5));
    Simulator::Run();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
   
     for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);
      std::cout << "Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress<< std::endl;
      std::cout << "Tx Packets   = " << iter->second.txPackets<< std::endl;
      std::cout << "Rx Packets   = " << iter->second.rxPackets<< std::endl;
      std::cout << "Lost Packets = " << iter->second.lostPackets<< std::endl;
      std::cout << "Throughput   = " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1000000  << " Kbps"<< std::endl;
    }

    Simulator::Destroy();

   
    return 0;
}
Program 3

 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ssid.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"

// Default Network Topology
//
//   Wifi 10.1.3.0
//                 AP
//  *    *    *    *
//  |    |    |    |    10.1.1.0
// n5   n6   n7   n0 -------------- n1   n2   n3   n4
//                   point-to-point  |    |    |    |
//                                   ================
//                                     LAN 10.1.2.0

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("ThirdScriptExample");

int
main(int argc, char* argv[])
{
    bool verbose = true;
    uint32_t nCsma = 4;
    uint32_t nWifi = 7;
    bool tracing = false;
    double simulationTime = 10.0;
    std::string socketType = "ns3::UdpSocketFactory";

    CommandLine cmd(__FILE__);
    cmd.AddValue("nCsma", "Number of \"extra\" CSMA nodes/devices", nCsma);
    cmd.AddValue("nWifi", "Number of wifi STA devices", nWifi);
    cmd.AddValue("verbose", "Tell echo applications to log if true", verbose);
    cmd.AddValue("tracing", "Enable pcap tracing", tracing);

    cmd.Parse(argc, argv);

    // The underlying restriction of 18 is due to the grid position
    // allocator's configuration; the grid layout will exceed the
    // bounding box if more than 18 nodes are provided.
    if (nWifi > 18)
    {
        std::cout << "nWifi should be 18 or less; otherwise grid layout exceeds the bounding box"
                  << std::endl;
        return 1;
    }

    if (verbose)
    {
        LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
        LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    }

    NodeContainer p2pNodes;
    p2pNodes.Create(2);

    PointToPointHelper pointToPoint;
    pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
    pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

    NetDeviceContainer p2pDevices;
    p2pDevices = pointToPoint.Install(p2pNodes);

    NodeContainer csmaNodes;
    csmaNodes.Add(p2pNodes.Get(1));
    csmaNodes.Create(nCsma);

    CsmaHelper csma;
    csma.SetChannelAttribute("DataRate", StringValue("300Mbps"));
    csma.SetChannelAttribute("Delay", TimeValue(NanoSeconds(6560)));

    NetDeviceContainer csmaDevices;
    csmaDevices = csma.Install(csmaNodes);

    NodeContainer wifiStaNodes;
    wifiStaNodes.Create(nWifi);
    NodeContainer wifiApNode = p2pNodes.Get(0);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    Ssid ssid = Ssid("ns-3-ssid");

    WifiHelper wifi;

    NetDeviceContainer staDevices;
    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
    staDevices = wifi.Install(phy, mac, wifiStaNodes);

    NetDeviceContainer apDevices;
    mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
    apDevices = wifi.Install(phy, mac, wifiApNode);

    MobilityHelper mobility;

    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX",
                                  DoubleValue(0.0),
                                  "MinY",
                                  DoubleValue(0.0),
                                  "DeltaX",
                                  DoubleValue(5.0),
                                  "DeltaY",
                                  DoubleValue(10.0),
                                  "GridWidth",
                                  UintegerValue(3),
                                  "LayoutType",
                                  StringValue("RowFirst"));

    mobility.SetMobilityModel("ns3::RandomWalk2dMobilityModel",
                              "Bounds",
                              RectangleValue(Rectangle(-50, 50, -50, 50)));
    mobility.Install(wifiStaNodes);

    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiApNode);

    InternetStackHelper stack;
    stack.Install(csmaNodes);
    stack.Install(wifiApNode);
    stack.Install(wifiStaNodes);

    Ipv4AddressHelper address;

    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfaces;
    p2pInterfaces = address.Assign(p2pDevices);

    address.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer csmaInterfaces;
    csmaInterfaces = address.Assign(csmaDevices);

    address.SetBase("10.1.3.0", "255.255.255.0");
    address.Assign(staDevices);
    address.Assign(apDevices);

   

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
   

 
  uint16_t port = 7;
    Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
    PacketSinkHelper packetSinkHelper(socketType, localAddress);
    ApplicationContainer sinkApp = packetSinkHelper.Install(csmaNodes.Get(3));

    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simulationTime + 0.1));

    uint32_t payloadSize = 3000;
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    OnOffHelper onoff(socketType, Ipv4Address::GetAny());
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
    onoff.SetAttribute("DataRate", StringValue("50Mbps")); // bit/s
    ApplicationContainer apps;

    InetSocketAddress rmt(csmaInterfaces.GetAddress(1), port);
    onoff.SetAttribute("Remote", AddressValue(rmt));
    onoff.SetAttribute("Tos", UintegerValue(0xb8));
    apps.Add(onoff.Install(wifiStaNodes.Get(1)));
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(simulationTime + 0.1));

   FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simulationTime + 5));
    Simulator::Run();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    std::cout << std::endl << "*** Flow monitor statistics ***" << std::endl;
    std::cout << "  Tx Packets/Bytes:   " << stats[1].txPackets << " / " << stats[1].txBytes
              << std::endl;

    std::cout << "  Rx Packets/Bytes:   " << stats[1].rxPackets << " / " << stats[1].rxBytes
              << std::endl;

    std::cout << "  Throughput: "
              << stats[1].rxBytes * 8.0 /
                     (stats[1].timeLastRxPacket.GetSeconds() -
                      stats[1].timeFirstRxPacket.GetSeconds()) /
                     1000000
              << " Mbps" << std::endl;
    std::cout << "  Mean delay:   " << stats[1].delaySum.GetSeconds() / stats[1].rxPackets
              << std::endl;
    std::cout << "  Mean jitter:   " << stats[1].jitterSum.GetSeconds() / (stats[1].rxPackets - 1)
              << std::endl;


    Simulator::Destroy();

    return 0;
}
Program 4
Inbox
Rajbala Khicher
	
AttachmentsTue, Mar 11, 2:37 PM
	
to Nishmitha, me, Divya
/*
 * Copyright (c) 2009 The Boeing Company
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

// This script configures two nodes on an 802.11b physical layer, with
// 802.11b NICs in adhoc mode, and by default, sends one packet of 1000
// (application) bytes to the other node.  The physical layer is configured
// to receive at a fixed RSS (regardless of the distance and transmit
// power); therefore, changing position of the nodes has no effect.
//
// There are a number of command-line options available to control
// the default behavior.  The list of available command-line options
// can be listed with the following command:
// ./ns3 run "wifi-simple-adhoc --help"
//
// For instance, for this configuration, the physical layer will
// stop successfully receiving packets when rss drops below -97 dBm.
// To see this effect, try running:
//
// ./ns3 run "wifi-simple-adhoc --rss=-97 --numPackets=20"
// ./ns3 run "wifi-simple-adhoc --rss=-98 --numPackets=20"
// ./ns3 run "wifi-simple-adhoc --rss=-99 --numPackets=20"
//
// Note that all ns-3 attributes (not just the ones exposed in the below
// script) can be changed at command line; see the documentation.
//
// This script can also be helpful to put the Wifi layer into verbose
// logging mode; this command will turn on all wifi logging:
//
// ./ns3 run "wifi-simple-adhoc --verbose=1"
//
// When you are done, you will notice two pcap trace files in your directory.
// If you have tcpdump installed, you can try this:
//
// tcpdump -r wifi-simple-adhoc-0-0.pcap -nn -tt
//

#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/double.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/log.h"
#include "ns3/mobility-helper.h"
#include "ns3/mobility-model.h"
#include "ns3/string.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WifiSimpleAdhoc");



int
main(int argc, char* argv[])
{
    std::string phyMode("DsssRate1Mbps");
    dBm_u rss{-80};
    uint32_t packetSize{1000}; // bytes
    uint32_t numPackets{1};
    Time interPacketInterval{"1s"};
    bool verbose{false};
   double simulationTime = 10; // seconds
    std::string transportProt = "Udp";
    std::string socketType;

   

    if (transportProt == "Tcp")
    {
        socketType = "ns3::TcpSocketFactory";
    }
    else
    {
        socketType = "ns3::UdpSocketFactory";
    }

    CommandLine cmd(__FILE__);
    cmd.AddValue("phyMode", "Wifi Phy mode", phyMode);
    cmd.AddValue("rss", "received signal strength", rss);
    cmd.AddValue("packetSize", "size of application packet sent", packetSize);
    cmd.AddValue("numPackets", "number of packets generated", numPackets);
    cmd.AddValue("interval", "interval between packets", interPacketInterval);
    cmd.AddValue("verbose", "turn on all WifiNetDevice log components", verbose);
    cmd.Parse(argc, argv);

    // Fix non-unicast data rate to be the same as that of unicast
    Config::SetDefault("ns3::WifiRemoteStationManager::NonUnicastMode", StringValue(phyMode));

    NodeContainer c;
    c.Create(10);

    // The below set of helpers will help us to put together the wifi NICs we want
    WifiHelper wifi;
    if (verbose)
    {
        WifiHelper::EnableLogComponents(); // Turn on all Wifi logging
    }
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper wifiPhy;
    // This is one parameter that matters when using FixedRssLossModel
    // set it to zero; otherwise, gain will be added
    wifiPhy.Set("RxGain", DoubleValue(0));
    // ns-3 supports RadioTap and Prism tracing extensions for 802.11b
    wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    // The below FixedRssLossModel will cause the rss to be fixed regardless
    // of the distance between the two stations, and the transmit power
    wifiChannel.AddPropagationLoss("ns3::FixedRssLossModel", "Rss", DoubleValue(rss));
    wifiPhy.SetChannel(wifiChannel.Create());

    // Add a mac and disable rate control
    WifiMacHelper wifiMac;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyMode),
                                 "ControlMode",
                                 StringValue(phyMode));
    // Set it to adhoc mode
    wifiMac.SetType("ns3::AdhocWifiMac");
    NetDeviceContainer devices = wifi.Install(wifiPhy, wifiMac, c);

    // Note that with FixedRssLossModel, the positions below are not
    // used for received signal strength.
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0.0, 0.0, 0.0));
    positionAlloc->Add(Vector(5.0, 0.0, 0.0));
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(c);

    InternetStackHelper internet;
    internet.Install(c);

    Ipv4AddressHelper ipv4;
    NS_LOG_INFO("Assign IP Addresses.");
    ipv4.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i = ipv4.Assign(devices);

   uint16_t port = 7;
    Address localAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
    PacketSinkHelper packetSinkHelper(socketType, localAddress);
    ApplicationContainer sinkApp = packetSinkHelper.Install(c.Get(8));

    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(simulationTime + 0.1));

    uint32_t payloadSize = 1448;
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    OnOffHelper onoff(socketType, Ipv4Address::GetAny());
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    onoff.SetAttribute("PacketSize", UintegerValue(payloadSize));
    onoff.SetAttribute("DataRate", StringValue("50Mbps")); // bit/s
    ApplicationContainer apps;

    InetSocketAddress rmt(i.GetAddress(8), port);
    onoff.SetAttribute("Remote", AddressValue(rmt));
    onoff.SetAttribute("Tos", UintegerValue(0xb8));
    apps.Add(onoff.Install(c.Get(2)));
    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(simulationTime + 0.1));

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(Seconds(simulationTime + 5));
    Simulator::Run();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    std::cout << std::endl << "* Flow monitor statistics *" << std::endl;
    std::cout << "  Tx Packets/Bytes:   " << stats[1].txPackets << " / " << stats[1].txBytes
              << std::endl;
   
    std::cout << "  Rx Packets/Bytes:   " << stats[1].rxPackets << " / " << stats[1].rxBytes
              << std::endl;
     
    std::cout << "  Dropped Packets/Bytes:   " << stats[1].lostPackets   << std::endl;
 
    std::cout << "  Throughput: "
              << stats[1].rxBytes * 8.0 /
                     (stats[1].timeLastRxPacket.GetSeconds() -
                      stats[1].timeFirstRxPacket.GetSeconds()) /
                     1000000
              << " Mbps" << std::endl;
    std::cout << "  Mean delay:   " << stats[1].delaySum.GetSeconds() / stats[1].rxPackets
              << std::endl;
    std::cout << "  Mean jitter:   " << stats[1].jitterSum.GetSeconds() / (stats[1].rxPackets - 1)
              << std::endl;
   

    Simulator::Destroy();

   
    return 0;
}

Program 8

/*
 * Copyright (c) 2015, IMDEA Networks Institute
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Hany Assasa <hany.assasa@gmail.com>
.*
 * This is a simple example to test TCP over 802.11n (with MPDU aggregation enabled).
 *
 * Network topology:
 *
 *   Ap    STA
 *   *      *
 *   |      |
 *   n1     n2
 *
 * In this example, an HT station sends TCP packets to the access point.
 * We report the total throughput received during a window of 100ms.
 * The user can specify the application data rate and choose the variant
 * of TCP i.e. congestion control algorithm to use.
 */

#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/log.h"
#include "ns3/mobility-helper.h"
#include "ns3/mobility-model.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/ssid.h"
#include "ns3/string.h"
#include "ns3/tcp-westwood-plus.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"

NS_LOG_COMPONENT_DEFINE("wifi-tcp");

using namespace ns3;

Ptr<PacketSink> sink;     //!< Pointer to the packet sink application
uint64_t lastTotalRx = 0; //!< The value of the last total received bytes



int
main(int argc, char* argv[])
{
    uint32_t payloadSize{1472};           /* Transport layer payload size in bytes. */
    DataRate dataRate{"100Mb/s"};         /* Application layer datarate. */
    std::string tcpVariant{"TcpNewReno"}; /* TCP variant type. */
    std::string phyRate{"HtMcs7"};        /* Physical layer bitrate. */
    Time simulationTime{"10s"};
             /* Simulation time. */
         
             
    bool pcapTracing{false};              /* PCAP Tracing is enabled or not. */

    /* Command line argument parser setup. */
    CommandLine cmd(__FILE__);
    cmd.AddValue("payloadSize", "Payload size in bytes", payloadSize);
    cmd.AddValue("dataRate", "Application data ate", dataRate);
    cmd.AddValue("tcpVariant",
                 "Transport protocol to use: TcpNewReno, "
                 "TcpHybla, TcpHighSpeed, TcpHtcp, TcpVegas, TcpScalable, TcpVeno, "
                 "TcpBic, TcpYeah, TcpIllinois, TcpWestwood, TcpWestwoodPlus, TcpLedbat ",
                 tcpVariant);
    cmd.AddValue("phyRate", "Physical layer bitrate", phyRate);
    cmd.AddValue("simulationTime", "Simulation time in seconds", simulationTime);
    cmd.AddValue("pcap", "Enable/disable PCAP Tracing", pcapTracing);
    cmd.Parse(argc, argv);

    tcpVariant = std::string("ns3::") + tcpVariant;
    // Select TCP variant
    TypeId tcpTid;
    NS_ABORT_MSG_UNLESS(TypeId::LookupByNameFailSafe(tcpVariant, &tcpTid),
                        "TypeId " << tcpVariant << " not found");
    Config::SetDefault("ns3::TcpL4Protocol::SocketType",
                       TypeIdValue(TypeId::LookupByName(tcpVariant)));

    /* Configure TCP Options */
    Config::SetDefault("ns3::TcpSocket::SegmentSize", UintegerValue(payloadSize));

    WifiMacHelper wifiMac;
    WifiHelper wifiHelper;
    wifiHelper.SetStandard(WIFI_STANDARD_80211n);

    /* Set up Legacy Channel */
    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::FriisPropagationLossModel", "Frequency", DoubleValue(5e9));

    /* Setup Physical Layer */
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.SetErrorRateModel("ns3::YansErrorRateModel");
    wifiHelper.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                       "DataMode",
                                       StringValue(phyRate),
                                       "ControlMode",
                                       StringValue("HtMcs0"));

    NodeContainer networkNodes;
    networkNodes.Create(3);
    Ptr<Node> apWifiNode = networkNodes.Get(0);
    Ptr<Node> staWifiNode = networkNodes.Get(1);

    /* Configure AP */
    Ssid ssid = Ssid("network");
    wifiMac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));

    NetDeviceContainer apDevice;
    apDevice = wifiHelper.Install(wifiPhy, wifiMac, apWifiNode);

    /* Configure STA */
    wifiMac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid));

    NetDeviceContainer staDevices;
    staDevices = wifiHelper.Install(wifiPhy, wifiMac, staWifiNode);

    /* Mobility model */
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0.0, 0.0, 0.0));
    positionAlloc->Add(Vector(1.0, 1.0, 0.0));

    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(apWifiNode);
    mobility.Install(staWifiNode);

    /* Internet stack */
    InternetStackHelper stack;
    stack.Install(networkNodes);

    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer apInterface;
    apInterface = address.Assign(apDevice);
    Ipv4InterfaceContainer staInterface;
    staInterface = address.Assign(staDevices);

    /* Populate routing table */
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    /* Install TCP Receiver on the access point */
    PacketSinkHelper sinkHelper("ns3::TcpSocketFactory",
                                InetSocketAddress(Ipv4Address::GetAny(), 9));
    ApplicationContainer sinkApp = sinkHelper.Install(apWifiNode);
    sink = StaticCast<PacketSink>(sinkApp.Get(0));

    /* Install TCP/UDP Transmitter on the station */
    OnOffHelper server("ns3::TcpSocketFactory", (InetSocketAddress(apInterface.GetAddress(0), 9)));
    server.SetAttribute("PacketSize", UintegerValue(payloadSize));
    server.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    server.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    server.SetAttribute("DataRate", DataRateValue(DataRate(dataRate)));
    ApplicationContainer serverApp = server.Install(staWifiNode);

    /* Start Applications */
    sinkApp.Start(Seconds(0.0));
    serverApp.Start(Seconds(1.0));
   

    /* Enable Traces */
    if (pcapTracing)
    {
        wifiPhy.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
        wifiPhy.EnablePcap("AccessPoint", apDevice);
        wifiPhy.EnablePcap("Station", staDevices);
    }

    /* Start Simulation */
 

     FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    Simulator::Stop(simulationTime + Seconds(1.0));
    Simulator::Run();

    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
   
     for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator iter = stats.begin (); iter != stats.end (); ++iter)
    {
      Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (iter->first);
      std::cout << "Flow ID: " << iter->first << " Src Addr " << t.sourceAddress << " Dst Addr " << t.destinationAddress<< std::endl;
      std::cout << "Tx Packets   = " << iter->second.txPackets<< std::endl;
      std::cout << "Rx Packets   = " << iter->second.rxPackets<< std::endl;
      std::cout << "Lost Packets = " << iter->second.lostPackets<< std::endl;
      std::cout << "Throughput   = " << iter->second.rxBytes * 8.0 / (iter->second.timeLastRxPacket.GetSeconds()-iter->second.timeFirstTxPacket.GetSeconds()) / 1000000  << " Kbps"<< std::endl;
    }

    Simulator::Destroy();


    }
    ﻿/*
 * Copyright (c) 2016
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Author: Sebastien Deronne <sebastien.deronne@gmail.com>
 */

#include "ns3/boolean.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/log.h"
#include "ns3/mobility-helper.h"
#include "ns3/on-off-helper.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/ssid.h"
#include "ns3/string.h"
#include "ns3/uinteger.h"
#include "ns3/yans-wifi-channel.h"
#include "ns3/yans-wifi-helper.h"

// This is a simple example in order to show how to configure an IEEE 802.11n Wi-Fi network
// with multiple TOS. It outputs the aggregated UDP throughput, which depends on the number of
// stations, the HT MCS value (0 to 7), the channel width (20 or 40 MHz) and the guard interval
// (long or short). The user can also specify the distance between the access point and the
// stations (in meters), and can specify whether RTS/CTS is used or not.

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("WifiMultiTos");

int
main(int argc, char* argv[])
{
    uint32_t nWifi{4};
    Time simulationTime{"10s"};
    meter_u distance{4.0};
    uint16_t mcs{7};
    uint8_t channelWidth{20}; // MHz
    bool useShortGuardInterval{false};
    bool useRts{false};

    CommandLine cmd(__FILE__);
    cmd.AddValue("nWifi", "Number of stations", nWifi);
    cmd.AddValue("distance",
                 "Distance in meters between the stations and the access point",
                 distance);
    cmd.AddValue("simulationTime", "Simulation time", simulationTime);
    cmd.AddValue("useRts", "Enable/disable RTS/CTS", useRts);
    cmd.AddValue("mcs", "MCS value (0 - 7)", mcs);
    cmd.AddValue("channelWidth", "Channel width in MHz", channelWidth);
    cmd.AddValue("useShortGuardInterval",
                 "Enable/disable short guard interval",
                 useShortGuardInterval);
    cmd.Parse(argc, argv);

    NodeContainer wifiStaNodes;
    wifiStaNodes.Create(nWifi);
    NodeContainer wifiApNode;
    wifiApNode.Create(1);

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211n);

    std::ostringstream oss;
    oss << "HtMcs" << mcs;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(oss.str()),
                                 "ControlMode",
                                 StringValue(oss.str()),
                                 "RtsCtsThreshold",
                                 UintegerValue(useRts ? 0 : 999999));

    Ssid ssid = Ssid("ns3-80211n");

    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid));

    NetDeviceContainer staDevices;
    staDevices = wifi.Install(phy, mac, wifiStaNodes);

    mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));

    NetDeviceContainer apDevice;
    apDevice = wifi.Install(phy, mac, wifiApNode);

    // Set channel width
    Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/ChannelSettings",
                StringValue("{0, " + std::to_string(channelWidth) + ", BAND_2_4GHZ, 0}"));

    // Set guard interval
    Config::Set(
        "/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/HtConfiguration/ShortGuardIntervalSupported",
        BooleanValue(useShortGuardInterval));

    // mobility
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator>();
    positionAlloc->Add(Vector(0.0, 0.0, 0.0));
    for (uint32_t i = 0; i < nWifi; i++)
    {
        positionAlloc->Add(Vector(distance, 0.0, 0.0));
    }
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiApNode);
    mobility.Install(wifiStaNodes);

    // Internet stack
    InternetStackHelper stack;
    stack.Install(wifiApNode);
    stack.Install(wifiStaNodes);
    Ipv4AddressHelper address;

    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer staNodeInterfaces;
    Ipv4InterfaceContainer apNodeInterface;

    staNodeInterfaces = address.Assign(staDevices);
    apNodeInterface = address.Assign(apDevice);

    // Setting applications
    ApplicationContainer sourceApplications;
    ApplicationContainer sinkApplications;
    std::vector<uint8_t> tosValues = {0x70, 0x28, 0xb8, 0xc0}; // AC_BE, AC_BK, AC_VI, AC_VO
    uint32_t portNumber = 9;
    for (uint32_t index = 0; index < nWifi; ++index)
    {
        for (uint8_t tosValue : tosValues)
        {
            auto ipv4 = wifiApNode.Get(0)->GetObject<Ipv4>();
            const auto address = ipv4->GetAddress(1, 0).GetLocal();
            InetSocketAddress sinkSocket(address, portNumber++);
            OnOffHelper onOffHelper("ns3::UdpSocketFactory", sinkSocket);
            onOffHelper.SetAttribute("OnTime",
                                     StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            onOffHelper.SetAttribute("OffTime",
                                     StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            onOffHelper.SetAttribute("DataRate", DataRateValue(50000000 / nWifi));
            onOffHelper.SetAttribute("PacketSize", UintegerValue(1472)); // bytes
            onOffHelper.SetAttribute("Tos", UintegerValue(tosValue));
            sourceApplications.Add(onOffHelper.Install(wifiStaNodes.Get(index)));
            PacketSinkHelper packetSinkHelper("ns3::UdpSocketFactory", sinkSocket);
            sinkApplications.Add(packetSinkHelper.Install(wifiApNode.Get(0)));
        }
    }

    sinkApplications.Start(Seconds(0.0));
    sinkApplications.Stop(simulationTime + Seconds(1.0));
    sourceApplications.Start(Seconds(1.0));
    sourceApplications.Stop(simulationTime + Seconds(1.0));

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    Simulator::Stop(simulationTime + Seconds(1.0));
    Simulator::Run();

    double throughput = 0;
    for (uint32_t index = 0; index < sinkApplications.GetN(); ++index)
    {
        double totalPacketsThrough =
            DynamicCast<PacketSink>(sinkApplications.Get(index))->GetTotalRx();
        throughput += ((totalPacketsThrough * 8) / simulationTime.GetMicroSeconds()); // Mbit/s
    }

    Simulator::Destroy();

    if (throughput > 0)
    {
        std::cout << "Aggregated throughput: " << throughput << " Mbit/s" << std::endl;
    }
    else
    {
        std::cout << "Obtained throughput is 0!" << std::endl;
        exit(1);
    }

    return 0;
}

   
    return 0;
}

﻿#include "ns3/aodv-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/ping-helper.h"
#include "ns3/point-to-point-module.h"
#include "ns3/yans-wifi-helper.h"
#include "ns3/flow-monitor-module.h"

#include <cmath>
#include <iostream>

using namespace ns3;

class AodvExample
{
  public:
    AodvExample();
    bool Configure(int argc, char** argv);
    void Run();
    void Report(std::ostream& os);

  private:
    uint32_t size;
    double step;
    double totalTime;
    bool pcap;
    bool printRoutes;

    NodeContainer nodes;
    NetDeviceContainer devices;
    Ipv4InterfaceContainer interfaces;

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor;

  private:
    void CreateNodes();
    void CreateDevices();
    void InstallInternetStack();
    void InstallApplications();
    void InstallFlowMonitor();
};

int main(int argc, char** argv)
{
    AodvExample test;
    if (!test.Configure(argc, argv))
    {
        NS_FATAL_ERROR("Configuration failed. Aborted.");
    }

    test.Run();
    test.Report(std::cout);
    return 0;
}

AodvExample::AodvExample()
    : size(10), step(50), totalTime(100), pcap(true), printRoutes(true)
{
}

bool AodvExample::Configure(int argc, char** argv)
{
    SeedManager::SetSeed(12345);
    CommandLine cmd(__FILE__);

    cmd.AddValue("pcap", "Write PCAP traces.", pcap);
    cmd.AddValue("printRoutes", "Print routing table dumps.", printRoutes);
    cmd.AddValue("size", "Number of nodes.", size);
    cmd.AddValue("time", "Simulation time, s.", totalTime);
    cmd.AddValue("step", "Grid step, m", step);

    cmd.Parse(argc, argv);
    return true;
}

void AodvExample::Run()
{
    CreateNodes();
    CreateDevices();
    InstallInternetStack();
    InstallApplications();
    InstallFlowMonitor();

    std::cout << "Starting simulation for " << totalTime << " s ...\n";

    Simulator::Stop(Seconds(totalTime));
    Simulator::Run();
    Simulator::Destroy();
}

void AodvExample::Report(std::ostream& os)
{
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

    std::cout << std::endl << "*** Flow monitor statistics ***" << std::endl;

    for (const auto& iter : stats)
    {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(iter.first);
        std::cout << "Flow ID: " << iter.first
                  << " Src Addr " << t.sourceAddress
                  << " Dst Addr " << t.destinationAddress << std::endl;
        std::cout << "Tx Packets   = " << iter.second.txPackets << std::endl;
        std::cout << "Rx Packets   = " << iter.second.rxPackets << std::endl;
        std::cout << "Lost Packets = " << iter.second.lostPackets << std::endl;

        double throughput = 0.0;
        if (iter.second.timeLastRxPacket.GetSeconds() - iter.second.timeFirstTxPacket.GetSeconds() > 0)
        {
            throughput = iter.second.rxBytes * 8.0 / (iter.second.timeLastRxPacket.GetSeconds() - iter.second.timeFirstTxPacket.GetSeconds()) / 1000000;
        }
        std::cout << "Throughput   = " << throughput << " Mbps" << std::endl;
    }
}

void AodvExample::CreateNodes()
{
    std::cout << "Creating " << (unsigned)size << " nodes " << step << " m apart.\n";
    nodes.Create(size);
    for (uint32_t i = 0; i < size; ++i)
    {
        std::ostringstream os;
        os << "node-" << i;
        Names::Add(os.str(), nodes.Get(i));
    }
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0),
                                  "MinY", DoubleValue(0.0),
                                  "DeltaX", DoubleValue(step),
                                  "DeltaY", DoubleValue(0),
                                  "GridWidth", UintegerValue(size),
                                  "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
}

void AodvExample::CreateDevices()
{
    WifiMacHelper wifiMac;
    wifiMac.SetType("ns3::AdhocWifiMac");
    YansWifiPhyHelper wifiPhy;
    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiPhy.SetChannel(wifiChannel.Create());
    WifiHelper wifi;
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode", StringValue("OfdmRate6Mbps"),
                                 "RtsCtsThreshold", UintegerValue(0));
    devices = wifi.Install(wifiPhy, wifiMac, nodes);

    if (pcap)
    {
        wifiPhy.EnablePcapAll(std::string("aodv"));
    }
}

void AodvExample::InstallInternetStack()
{
    AodvHelper aodv;
    InternetStackHelper stack;
    stack.SetRoutingHelper(aodv);
    stack.Install(nodes);
    Ipv4AddressHelper address;
    address.SetBase("10.0.0.0", "255.0.0.0");
    interfaces = address.Assign(devices);

    if (printRoutes)
    {
        Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper>("aodv.routes", std::ios::out);
        Ipv4RoutingHelper::PrintRoutingTableAllAt(Seconds(8), routingStream);
    }
}

void AodvExample::InstallApplications()
{
    PingHelper ping(interfaces.GetAddress(size - 1));
    ping.SetAttribute("VerboseMode", EnumValue(Ping::VerboseMode::VERBOSE));

    ApplicationContainer p = ping.Install(nodes.Get(0));
    p.Start(Seconds(0));
    p.Stop(Seconds(totalTime) - Seconds(0.001));

    Ptr<Node> node = nodes.Get(size / 2);
    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
    Simulator::Schedule(Seconds(totalTime / 3),
                        &MobilityModel::SetPosition,
                        mob,
                        Vector(1e5, 1e5, 1e5));
}

void AodvExample::InstallFlowMonitor()
{
    monitor = flowmon.InstallAll();
}
