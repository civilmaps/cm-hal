#include "quanergy_server_derived.h"

using namespace std;
using namespace Poco::Net;

namespace cm {

    void Quanergy_Server_Derived::init(Json::Value my_config, Broadcast_Queue<point_t> *my_reg_records, bool my_log_data = false, string my_dir=""){
        tcp_port = my_config["settings"]["data_port"].asUInt();//assign tcp port to filter incoming packets
        m8_ip_address = my_config["settings"]["ip_address"].asString();
        interface = my_config["settings"]["iface"].asString();
        print_points_to_terminal = my_config["logging"]["print_points_to_terminal"].asBool();
        print_points_to_file = my_config["logging"]["print_points_to_file"].asBool();
        is_des = my_config["settings"]["is_des"].asBool();
        
        if (my_config["settings"]["lidar_type"] == "QUANERGY_M8_TYPE") {
            lidar_type = QUANERGY_M8_TYPE;
        } else {
            cout <<"unknown lidar_type in lidar sensor config[\"settings\"][\"lidar_type\"]"<<endl;
            exit(-1);
        }
        near_clip = my_config["settings"]["near_clip"].asDouble();
        far_clip = my_config["settings"]["far_clip"].asDouble();
        //overwrite_time = my_config["settings"]["overwrite_time"].asBool();
        
        reg_records = my_reg_records;
        log_data = my_log_data;
        if(log_data) {
            const unsigned int num_packets_per_file = 100000;
            my_laser_file_writer = new incremental_laser_writer(num_packets_per_file, my_dir+"pcaps/"+"quanergy_output", lidar_type);
        }
        //Initialize a socket object
        StreamSocket my_stream_socket();
    };

    Quanergy_Server_Derived::~Quanergy_Server_Derived(){
    };

    bool Quanergy_Server_Derived::getBytes(){ 
        int bytes_available = this->my_stream_socket.available();
        if (bytes_available > 0) {
            try {
                this->my_stream_socket.receiveBytes(this->receive_buffer, bytes_available);
            } 
            catch (Poco::Exception error) {
                cout << "recv failed (Error: " << error.displayText() << ')' << endl;
                return false;
            }
        }
        return true;
    }

    void Quanergy_Server_Derived::openSocket(){
        //Create socket address object
        SocketAddress my_socket_address(this->m8_ip_address, this->tcp_port);
        //Try to connect to the socket
        try {
            //Connect using the parameters in my_socket_address, non-blocking
            this->my_stream_socket.connectNB(my_socket_address);
        }
        catch (Poco::Exception error) {
            cout << "Connection failed (Error: " << error.displayText() << ')' << endl;
            return;
        }
    }
    
    void Quanergy_Server_Derived::runTask(){
        // Get boresighting info
        cv::Mat boresight_mat = get_boresight_mat_from_config(boresight_config);
    
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* descr;
        struct pcap_pkthdr *pkthdr;
        const uint8_t *packet;
        uint16_t curr_tcp_port;
        //M8_complete_packet curr_m8_packet; 
        double time_since_start = 0;
        vector<point_t> temp_laser_records;
        char temp_data[M8_PACKET_SIZE];
        laser_decoder my_laser_decoder(lidar_type);
        my_laser_decoder.set_range(near_clip,far_clip);// default to 2.5, 200meters. In office testing: 0.05, 30
        unsigned int i, temp_laser_records_size;

        printf("My tcp port in quanergy_server class: %i\n", this->tcp_port);
        cout << "My ip address in quanergy_server class: " << this->m8_ip_address << ".\n";

        //Open the packet capture
        descr = pcap_open_live(interface.c_str(),BUFSIZ,0,-1,errbuf);
        if(descr == NULL) { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

        //Open the TCP socket if we are running in real time, not DES
        if(!is_des){
            this->openSocket();
        }
        
        //Check for packets and process received packets
        FILE * my_point_log_file;
        my_point_log_file = fopen (my_point_log_file_name.c_str(),"w");
        while(!this->isCancelled()){
            this->getBytes();
            if(pcap_next_ex(descr, &pkthdr, &packet)) { //PACK
                //Big endian ip port, grab it from the packet
                curr_tcp_port = packet[34]*256 + packet[35];
                //printf("curr_tcp_port: %i\n", curr_tcp_port);
                if(curr_tcp_port == this->tcp_port){
                    //Copy the ethernet packet to temp_data
                    memcpy(temp_data, packet + BYTES_TO_SKIP_TO_M8_HEADER, sizeof(temp_data));

                    //TODO: Handle pcap timestamp if from des, add timestamp to last 8 bytes
                    //assumes the machine clock is in utc and that the kernel has been compiled with the flag for capturing packet timestamps
                    time_since_start = (pkthdr->ts.tv_sec) + (pkthdr->ts.tv_usec) / 1000000.00; 
                    my_laser_decoder.get_records_from_packet(temp_data, time_since_start, temp_laser_records);    
                    
                    // Boresight the points before pushing to vector
                    boresight(temp_laser_records, boresight_mat);

                     //Debug
                    temp_laser_records_size = temp_laser_records.size();
                    
                    if (temp_laser_records_size > 2 && print_points_to_terminal) {
                        //cout <<setprecision (15)<<"laser processed time 0, 1: "<<temp_laser_records[0].time<<", "<<temp_laser_records[1].time<<endl;
                        cout <<"coords 0: "<<temp_laser_records[0].x_relative<<", "<<temp_laser_records[0].y_relative<<", "<<temp_laser_records[0].z_relative<<endl;
                    }
                    
                    for (i=0;i<temp_laser_records_size;i++) {
                        reg_records->try_enqueue(temp_laser_records[i]);
                        if (print_points_to_file) {
                            fprintf(my_point_log_file, "%10.2f %10.2f %10.2f %10.1f\n",
                                temp_laser_records[i].x_relative,
                                temp_laser_records[i].y_relative,
                                temp_laser_records[i].z_relative,
                                temp_laser_records[i].intensity);
                        }
                    }

                    //clear the temporary vector: feels like this isn't great for memory allocation
                    //TODO we know how many records each packet contains, so we can make sure the vector is in a constant memory space
                    temp_laser_records.clear();

                    //copy quanergy cap to local disk
                    if(log_data) {
                        my_laser_file_writer->write_packet(pkthdr, const_cast<unsigned char *>(packet));
                    }
                }
            } 
        }
    }
}
