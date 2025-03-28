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

