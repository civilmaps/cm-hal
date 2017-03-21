#ifndef __LASER_IO_H
#define __LASER_IO_H

#include <pcap.h>
#include <string>
#include <math.h>
#include <cstring>
#include <vector>
#include <cstdio>
#include "m8_packet_structures.h"
#include "../cm_types/point.h"

// Some versions of libpcap do not have PCAP_NETMASK_UNKNOWN
#if !defined(PCAP_NETMASK_UNKNOWN)
  #define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

using namespace std;

namespace cm {

/********** Defines ***************/
const int NUM_ROT_ANGLES = 36001;
const int LASER_PER_FIRING = 32;
const int MAX_NUM_LASERS = 64;
const int FIRING_PER_PKT = 12;
const int VELO_DATA_LENGTH = 1206;
const unsigned int VELO_BYTES_TO_SKIP = 42; // The ethernet header is 42 bytes long; unnecessary
static const double HOUR_IN_US = 3600.0 * 1e6; //One hour represented in microseconds
static const long MAX_TIME_DIFFERENCE = 1000000 * 60 * 29; // microseconds

enum HDLBlock
{
    BLOCK_0_TO_31 = 0xeeff,
    BLOCK_32_TO_63 = 0xddff
};

typedef enum lidar_type_t
{
    QUANERGY_M8_TYPE = 8,
        VELO_16_TYPE = 16,
        VELO_32_TYPE = 32,
        VELO_64_TYPE = 64
} lidar_type_t;

const float ELEVATION_ANGLES_32 [] = {
    -30.67,
    -9.33,
    -29.33,
    -8.00,
    -28.00,
    -6.66,
    -26.66,
    -5.33,
    -25.33,
    -4.0,
    -24.00,
    -2.67,
    -22.67,
    -1.33,
    -21.33,
    0,
    -20.00,
    1.33,
    -18.67,
    2.67,
    -17.33,
    4,
    -16.00,
    5.33,
    -14.67,
    6.67,
    -13.33,
    8,
    -12.00,
    9.33,
    -10.67,
    10.67
};

const float ELEVATION_ANGLES_16 [] = {
    -15,
    1,
    -13,
    3,
    -11,
    5,
    -9,
    7,
    -7,
    9,
    -5,
    11,
    -3,
    13,
    -1,
    15,
    -15,
    1,
    -13,
    3,
    -11,
    5,
    -9,
    7,
    -7,
    9,
    -5,
    11,
    -3,
    13,
    -1,
    15
};

const float ELEVATION_ANGLES_COS_RAD_32 [] = {
   0.860119473364679,
   0.986770965571766,
   0.871812912849925,
   0.990268068741570,
   0.882947592858927,
   0.993251859042339,
   0.893684854429880,
   0.995676196568517,
   0.903858661687312,
   0.997564050259824,
   0.913545457642601,
   0.998914402915095,
   0.922740022918746,
   0.999730593220608,
   0.931500901980512,
   1.000000000000000,
   0.939692620785908,
   0.999730593220608,
   0.947378020466135,
   0.998914402915095,
   0.954604963513407,
   0.997564050259824,
   0.961261695938319,
   0.995676196568517,
   0.967400487527919,
   0.993231602049105,
   0.973058285620620,
   0.990268068741570,
   0.978147600733806,
   0.986770965571766,
   0.982709876657223,
   0.982709876657223
};

const float ELEVATION_ANGLES_COS_RAD_16 [] = {
    0.965925883522,
    0.999847695414,
    0.974370107897,
    0.998629537069,
    0.98162721439,
    0.996194704516,
    0.987688361351,
    0.992546164218,
    0.992546164218,
    0.987688361351,
    0.996194704516,
    0.98162721439,
    0.998629537069,
    0.974370107897,
    0.999847695414,
    0.965925883522,
    0.965925883522,
    0.999847695414,
    0.974370107897,
    0.998629537069,
    0.98162721439,
    0.996194704516,
    0.987688361351,
    0.992546164218,
    0.992546164218,
    0.987688361351,
    0.996194704516,
    0.98162721439,
    0.998629537069,
    0.974370107897,
    0.999847695414,
    0.965925883522
};

const float ELEVATION_ANGLES_SIN_RAD_32 [] = {
  -0.510092630351456,
  -0.162120515372252,
  -0.489838999047777,
  -0.139173100960065,
  -0.469471562785891,
  -0.115977344808961,
  -0.448695198283472,
  -0.092891934993581,
  -0.427831181300314,
  -0.069756473744125,
  -0.406736643075800,
  -0.046583426760803,
  -0.385422949633143,
  -0.023210794445087,
  -0.363739013042995,
                   0,
  -0.342020143325669,
   0.023210794445087,
  -0.320116988517741,
   0.046583426760803,
  -0.297874744877048,
   0.069756473744125,
  -0.275637355816999,
   0.092891934993581,
  -0.253251449612328,
   0.116150698194064,
  -0.230559260896326,
   0.139173100960065,
  -0.207911690817759,
   0.162120515372252,
  -0.185152095101151,
   0.185152095101151
};

const float ELEVATION_ANGLES_SIN_RAD_16 [] = {
    -0.258818831505,
    0.0174523916974,
    -0.224950867608,
    0.0523359120771,
    -0.190808836192,
    0.0871556693173,
    -0.156434333994,
    0.121869240979,
    -0.121869240979,
    0.156434333994,
    -0.0871556693173,
    0.190808836192,
    -0.0523359120771,
    0.224950867608,
    -0.0174523916974,
    0.258818831505,
    -0.258818831505,
    0.0174523916974,
    -0.224950867608,
    0.0523359120771,
    -0.190808836192,
    0.0871556693173,
    -0.156434333994,
    0.121869240979,
    -0.121869240979,
    0.156434333994,
    -0.0871556693173,
    0.190808836192,
    -0.0523359120771,
    0.224950867608,
    -0.0174523916974,
    0.258818831505
};

//note these values are little endian, pcap wants the packet header and
//data to be in the platform's native byte order, so assuming little endian.
const unsigned short lidar_packet_header[21] = {
    0xffff, 0xffff, 0xffff, 0x7660,
    0x0088, 0x0000, 0x0008, 0x0045,
    0xd204, 0x0000, 0x0040, 0x11ff,
    0xaab4, 0xa8c0, 0xc801, 0xffff, // checksum 0xa9b4 //source ip 0xa8c0, 0xc801 is 192.168.1.200
    0xffff, 0x4009, 0x4009, 0xbe04, 0x0000};

//--------------------------------------------------------------------------------
const unsigned short position_packet_header[21] = {
    0xffff, 0xffff, 0xffff, 0x7660,
    0x0088, 0x0000, 0x0008, 0x0045,
    0xd204, 0x0000, 0x0040, 0x11ff,
    0xaab4, 0xa8c0, 0xc801, 0xffff, // checksum 0xa9b4 //source ip 0xa8c0, 0xc801 is 192.168.1.200
    0xffff, 0x7420, 0x7420, 0x0802, 0x0000};


#define to_radians(x) ((x) * M_PI / 180.0)

#pragma pack(push, 1)
typedef struct laser_return_t
{
    unsigned short distance;
    unsigned char intensity;
} laser_return_t;

struct firing_data_t
{
    unsigned short block_identifier;
    unsigned short rotational_position;
    laser_return_t laser_returns[LASER_PER_FIRING];
};

struct data_packet_t
{
    firing_data_t firing_data[FIRING_PER_PKT];
    unsigned int gps_timestamp;
    unsigned char blank1;
    unsigned char blank2;
};

struct laser_correction_t
{
    double azimuthCorrection;
    double verticalCorrection;
    double distanceCorrection;
    double verticalOffsetCorrection;
    double horizontalOffsetCorrection;
    double sinVertCorrection;
    double cosVertCorrection;
    double sinVertOffsetCorrection;
    double cosVertOffsetCorrection;
};

struct rgb_t
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

#pragma pack(pop)

/********* Classes ************/
/**
    Laser file reader class to read in and decode pcaps and laser blobs
*/
class laser_file_reader {
public:
    /**
    Laser file reader constructor
    */
    laser_file_reader(unsigned int my_num_lasers);

    /**
    Laser file reader desctuctor
    */
    ~laser_file_reader();

    /**
    Closing function to close an open file
    */
    void my_close();
    /**
    Opening function for pcap file
    */
    bool my_open(const string& filename);
    /**
    Same as my_open, but treats a string as a file for the benefit of
    libpcap (which only handles files).
    Remember that the pointer returned by blob.c_str() is valid only while
    blob stays unmodified.
    */
    bool my_open_str(const string& blob);
    /**
    Checks if the pcap file is open
    */
    bool is_open();
    /**
    Returns the pcap file name 
    */
    const string& get_file_name();
    /**
    Returns the last error from attempting to open the pcap file
    */
    const string& get_last_error();
    /**
    Gets our position in the current pcap file
    */
    void get_file_position(fpos_t* position);
    /**
    Sets our position in the current pcap file
    */
    void set_file_position(fpos_t* position);
    /**
    Grabs and processes the next packet in the pcap file
    */
    bool next_packet(const unsigned char*& data, unsigned int& data_length, double& time_since_start, pcap_pkthdr** header_reference);

protected:
    double get_elapsed_time(const struct timeval& end, const struct timeval& start);
    pcap_t* my_pcap_file;
    string file_name;
    string last_error;
    struct timeval start_time;
    unsigned int num_lasers;
};

class laser_decoder {
public:
    laser_decoder(unsigned int my_num_lasers);
    //~laser_decoder();
    void read_velo_file(string filename, vector<point_t> &laser_records);//change this buffer to what it should be
    void read_velo_str(string &blob, vector<point_t> &laser_records);
    double compute_timestamp(double udp_timestamp, unsigned int top_hour_timestamp);
    bool does_udp_hour_match_velodyne(double udp_timestamp, unsigned int velodyne_timestamp);
    double get_correct_top_of_hour(double udp_timestamp, unsigned int velodyne_timestamp);
    void get_records_from_packet(const char *data_packet_bytes, double packet_timestamp, vector<point_t> &laser_records);
    //void get_records_from_packet(const data_packet_t *data_packet, double packet_timestamp, vector<point_t> &laser_records);
    //void get_records_from_packet(const M8_data_packet *data_packet, double packet_timestamp, vector<point_t> &laser_records);
    void set_range(float range_min, float range_max);
    void set_log_mode(bool mode);
    void set_output_log_file(string file_path);
    void set_num_packets_to_read(int num_packets);
    /*  Top of hour functions below:
    set_top_of_hour_override() and set_override_pcap_time() allow the top of hour timestamp 
    that is sent to the laser decoder to be modified on the fly, so that another 
    time stamp can be used other than the OS time from the pcap ethernet header.
    Example use: If the OS time from the ethernet header is incorrect, or you want to apply
    any other time correction to the pcap without directly modifying the pcap packet headers themselves.

    NOTE: In order to function correctly, the aggregate sample data must be 1 hour or less in length.*/
    void set_top_of_hour(double top_hour_timestamp);
    void set_override_pcap_time(bool toggle);
    
private:
    laser_file_reader *reader;//this is the file reader the decoder object uses
    double last_timestamp;
    float range_min, range_max;
    unsigned int num_lasers;
    double M8_HORIZONTAL_ANGLE_LOOKUP_TABLE[M8_NUM_ROT_ANGLES+1];
    laser_correction_t HDL64_laser_config[64]; //Holds the configuration for each laser in an HDL64
    bool HDL64_config_loaded;
    bool output_log_mode;
    string output_log_file;
    FILE * myfile;
    int num_packets_to_read;
    double top_of_hour_override; 
    bool override_pcap_time; 
    void check_top_of_hour_override_time(double &packet_timestamp);
};

//I like not to indent what is inside the namespace braces.
}

#endif
