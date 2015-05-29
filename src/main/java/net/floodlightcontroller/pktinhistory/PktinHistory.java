package net.floodlightcontroller.pktinhistory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.swing.text.html.HTML;

import net.floodlightcontroller.loadbalancer.ILoadBalancerService;
import net.floodlightcontroller.loadbalancer.LBMember;
import net.floodlightcontroller.loadbalancer.LBPool;
import net.floodlightcontroller.loadbalancer.LBVip;
import net.floodlightcontroller.loadbalancer.LoadBalancer;
import net.floodlightcontroller.loadbalancer.LoadBalancer.IPClient;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.Controller;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.devicemanager.internal.Device;
import net.floodlightcontroller.forwarding.Forwarding;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.PacketParsingException;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.storage.StorageSourceNotification.Action;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.util.FlowModUtils;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JMemory.Type;
import org.jnetpcap.packet.JMemoryPacket;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.protocol.network.Ip4;
import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFFactory;
import org.projectfloodlight.openflow.protocol.OFFlowAdd;
import org.projectfloodlight.openflow.protocol.OFFlowDelete;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.U64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hicham.jnet.ClassicPcapExample;
import com.sun.xml.internal.ws.model.AbstractWrapperBeanGenerator.BeanMemberFactory;

public class PktinHistory implements IFloodlightModule, IOFMessageListener{
    protected IFloodlightProviderService floodlightProvider;
    protected static Logger logger;
    protected IPv4 myIP;
    protected TCP tcp;
    protected UDP udp;
    protected MacAddress destMac;
    protected IPv4Address destIP;
    protected ServerSocket ServerSocket;    
    private Data data = new Data();
    private byte [] bytes = new byte[100];
    ClassicPcapExample pcap;
    ClamAVUtil clam;
    class MyThread extends Thread
    {
    	 Thread t;
    	 int indice; // name of thread

    	  MyThread(int _indice) {
    	    indice = _indice;
    	    t = new Thread(this,indice + "");
    	    logger.info("New thread: " + t);
    	    t.start(); // Start the thread
    	  }
    	boolean search(String URI ,String word,boolean isFile)
    	{
    		boolean t=false;
    		if(isFile == false)
    		{
    			if(URI.contains(word))
    			     t=true;
    				
    		}
    		
    		else if(isFile==true)	
    		{
    	        try {

    	            // Open the file c:\test.txt as a buffered reader

    	            BufferedReader bf = new BufferedReader(new FileReader(URI));

    	             

    	            // Start a line count and declare a string to hold our current line.

    	            int linecount = 0;

    	                String line;

    	 

    	            // Let the user know what we are searching for

    	            logger.info("Searching for " + "facebook.com" + " in file...");

    	 

    	            // Loop through each line, stashing the line into our line variable.

    	            while (( line = bf.readLine()) != null)

    	            {

    	                    // Increment the count and find the index of the word

    	                    linecount++;

    	                    int indexfound = line.indexOf(word);

    	 

    	                    // If greater than -1, means we found the word

    	                    if (indexfound > -1) {

    	                         logger.info("Word was found at position " + indexfound + " on line " + linecount);
    	                         t=true;

    	                    }

    	            }

    	 

    	            // Close the file after done searching

    	            bf.close();
    	        }
    	        catch (IOException e) {

    	           logger.info("IO Error Occurred: " + e.toString());

    	        }
    	}
    		return t;
    	}
    	@Override
    	public void run() {
          
    	}
    	
    }
    @Override
    public String getName() {
        // TODO Auto-generated method stub
        return PktinHistory.class.getSimpleName();
    }

    @Override
    public boolean isCallbackOrderingPrereq(OFType type, String name) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isCallbackOrderingPostreq(OFType type, String name) {
        // TODO Auto-generated method stub
        if(type==OFType.PACKET_IN && name.equalsIgnoreCase(Forwarding.class.getSimpleName()))
            return true;
        else
        return false;
    }

    
    
    
    @Override
    public net.floodlightcontroller.core.IListener.Command receive(
            IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
        logger.info("Get In");
        //clam.run();
        // TODO Auto-generated method stub
        switch (msg.getType()) {

        case PACKET_IN:
            Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,
                    IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
            destMac = eth.getDestinationMACAddress();
            
            
            if(eth.getEtherType().getValue()==Ethernet.TYPE_ARP)
            {
                logger.info("ARP");
                return Command.CONTINUE;
            }
            
            else if (eth.getEtherType().getValue()==Ethernet.TYPE_IPv4) {
                logger.info("IPv4");
                myIP = (IPv4) eth.getPayload();
                destIP = myIP.getDestinationAddress();

                if(myIP.getProtocol().equals(IpProtocol.ICMP))
                {
                    logger.info("ICMP");
                    return Command.CONTINUE;
                }
               
                else if (myIP.getProtocol().equals(IpProtocol.TCP)) {
                    logger.info("TCP");
                    tcp = (TCP) myIP.getPayload();
                    
                   
                   
                    if (tcp.getDestinationPort().equals(TransportPort.of(80))||tcp.getSourcePort().equals(TransportPort.of(80))||tcp.getDestinationPort().equals(TransportPort.of(443))||tcp.getSourcePort().equals(TransportPort.of(443))) {
                    	
                    	data = (Data)tcp.getPayload();//the http header is the payload of the tcp packet
                        bytes = data.getData();
                       
                        /** 
                         * Set the capture. We capture 6 packets, use a 5 second timeout 
                         * on reassembly buffers and we supply our reassembly handler (our 
                         * application) as the recipient of packets from libpcap. To it, 
                         * we supply an anonymous handler that receives the reassembly 
                         * buffers. We simply convert those to packets and print them out. 
                         * If the buffer is incomplete, meaning it was timed out before we 
                         * received the last IP fragment, we simply report the event as an 
                         * warning. 
                         */  
                       
                            if(bytes.length==0)
                        {
                         
                        //OFFlowDelete flowDelete =  sw.getOFFactory().buildFlowDelete().build();
    					//sw.write(flowDelete);
                        Ethernet e = new Ethernet();
                        e.setSourceMACAddress(MacAddress.of(1));
                        e.setDestinationMACAddress(MacAddress.of(2));
                       
                        IPv4 ipv4 = new IPv4();
                        ipv4.setSourceAddress(IPv4Address.of("192.168.56.100"));
                        ipv4.setDestinationAddress(IPv4Address.NO_MASK);
                       
                        TCP t = new TCP();
                        TransportPort tc=null;
                        if(!tcp.getDestinationPort().equals(TransportPort.of(80)))
                            tc=tcp.getDestinationPort();
                            else
                                tc=tcp.getSourcePort();
                        t.setSourcePort(tc);
                       
                        e.setPayload(ipv4);
                        ipv4.setPayload(t);
                        t.setPayload(data);
                       
                        OFActionOutput output= sw.getOFFactory().actions().buildOutput()
                                .setPort(OFPort.FLOOD)
                                .build();
                       
                        OFPacketOut.Builder myPacketOut = sw.getOFFactory().buildPacketOut()
                                .setData(eth.serialize())
                                .setBufferId(OFBufferId.NO_BUFFER)
                                .setActions(Collections.singletonList((OFAction)output));
                       
                        sw.write(myPacketOut.build());
                       
                        }
                         else
                        {
                        //logger.info(bytes +" "+bytes.length);
                        String s = new String(bytes);
                        logger.info(s +" "+bytes.length);
                        int beginIndex = s.indexOf("Host");
						int endIndex = s.indexOf("Accept");
						String a = null;
						if(beginIndex!=-1 && endIndex!=-1)
						{
							try
						  {
							a  = s.substring(beginIndex+6,endIndex);
							logger.info("We made it 1");
							logger.info(a.trim());
						  }
							catch(Exception e){}
						}
						
						beginIndex = s.indexOf("Referer");
						endIndex = s.indexOf("Connection");
					    String b = null;
						if(beginIndex!=-1 && endIndex!=-1)
						{
							try
						  {
							b  = s.substring(beginIndex+9,endIndex);
							logger.info("We made it 2");
							logger.info(b.trim());
						  }
							catch(Exception e){}
						}
						
						beginIndex = s.indexOf("GET");
					    endIndex  = s.indexOf("User-Agent");
					    String c=null;
					    if(beginIndex!=-1 && endIndex!=-1)
						{
							try
						  {
							c  = s.substring(beginIndex+4,endIndex);
							logger.info("We made it 3");
							logger.info(c.trim());
						  }
							catch(Exception e){}
						}
						MyThread  t = new MyThread (0);

						if(c!=null && t.search(c,"download",false))
						{
					      logger.info("test");
						  eth.setDestinationMACAddress(MacAddress.of(1));
                          myIP.setDestinationAddress(IPv4Address.of("192.168.56.100"));
                          tcp.setDestinationPort(8000); 
                          return Command.STOP;
						}
						
						if(b!=null && t.search(b,"download",false))
						{
						  eth.setDestinationMACAddress(MacAddress.of(1));
                          myIP.setDestinationAddress(IPv4Address.of("192.168.56.100"));
                          tcp.setDestinationPort(8000); 
                          return Command.STOP;
						}
						
						
						if(a!=null && t.search("./BL/socialnet/domains",a.trim(),true));
						{	
							eth.setDestinationMACAddress(MacAddress.of(1));
                            myIP.setDestinationAddress(IPv4Address.of("192.168.56.100"));
                            
		                 
						    /*
						     LBMember member = new LBMember();
						    
						    k.members = new HashMap<String,LBMember>();
						    k.memberIpToId = new HashMap<Integer,String>();
						    k.createMember(member);
						    member.address = myIP.getSourceAddress().getInt();

						    k.vips = new HashMap<String, LBVip>();
						    k.pools = new HashMap<String, LBPool>();
						    
						    LBPool l = new LBPool();
						    member.poolId = l.id;
						    k.createPool(l);
						   
						    IPClient client = k.new IPClient(); // because IPClient is an internal class to LoadBalancer
							client.ipAddress = IPv4Address.of("10.0.0.1");
							client.srcPort = tcp.getDestinationPort();
							client.targetPort = tcp.getSourcePort();
							
						    k.pushBidirectionalVipRoutes(sw,(OFPacketIn)msg, cntx, client, member);
						    //return Command.STOP;
						     
						     */
						}
						
                        logger.info("We have succeeded");
                        logger.info("Get Out");
                        return Command.CONTINUE;
                        }
                    }
                   
                }
               
                else if (myIP.getProtocol().equals(IpProtocol.UDP)) {
                    logger.info("UDP");
                    udp = (UDP) myIP.getPayload();
                   
                    if(udp.getDestinationPort().equals(TransportPort.of(53)))
                    {
                        logger.info("DNS");
                        return Command.CONTINUE;
                    }
                   
                    else if(udp.getSourcePort().equals(TransportPort.of(53)))
                    {
                        logger.info("Getting destination ip address from DNS server");
                        return Command.CONTINUE;
                    }
                 }
              }
            break;

        default:
            break;
            }

        return Command.STOP;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleServices() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
        // TODO Auto-generated method stub
        Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
        l.add(IFloodlightProviderService.class);
        return l;
    }

    @Override
    public void init(FloodlightModuleContext context)
            throws FloodlightModuleException {
        floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		//k.init(context);
        logger = LoggerFactory.getLogger(PktinHistory.class);
        pcap = new ClassicPcapExample();
        clam = new ClamAVUtil();
        //pcap.run();
    }

    @Override
    public void startUp(FloodlightModuleContext context) {
        floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
        // TODO Auto-generated method stub

    }

	/*@Override
	public void nextPacket(PcapPacket packet, Object user) {
		// TODO Auto-generated method stub
	}
	*/
}