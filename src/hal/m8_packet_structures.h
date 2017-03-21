/** \file m8_packet_header.h
  * \brief Provide base deserialization functionality.
  */

#ifndef QUANERGY_CLIENT_PACKET_STRUCTURE_H
#define QUANERGY_CLIENT_PACKET_STRUCTURE_H

#include <cstdint>
#include <vector>
#include <algorithm>
#include <arpa/inet.h>
#include <iostream>

using namespace std;

namespace cm
{
  //Quanergy M8 defines
  // Default number of firings per TCP packet
  const unsigned int M8_FIRING_PER_PKT = 50;
  // M8 packet supports multiecho return
  const unsigned int M8_NUM_RETURNS = 3;
  // The total number of lasers on the M8 Sensor
  const unsigned int M8_NUM_LASERS = 8;
  //Number of rotatation angles of the M8
  const int32_t M8_NUM_ROT_ANGLES = 10400;
  // The header signature for all data packets from the Quanergy M8 
  const uint32_t M8_SIGNATURE = 0x75bd7e97;
  const unsigned int M8_FULL_PACKET_SIZE = 6698; //6632 bytes for Quanergy packet, 66 bytes from ethernet header
  const unsigned int M8_PACKET_SIZE = 6632;
  const unsigned int BYTES_TO_SKIP_TO_M8_HEADER = 66; //Bytes to skip to the relevent M8 packet, difference between M8_FULL_PACKET_SIZE and M8_PACKET_SIZE

  //Fixed verticle angles in degrees
  const double ELEVATION_ANGLES_M8 [] = {
    -18.248992253814286, 
    -15.42402384492176, 
    -12.490995595867565, 
    -9.464976296663636, 
    -6.360003413290677, 
    -3.1970013644268698, 
    0.0, 
    3.1970013644268698
  };

  //Fixed verticle angles in radians
  const double ELEVATION_ANGLES_RAD_M8 [] = {
    -0.318505, 
    -0.2692, 
    -0.218009, 
    -0.165195, 
    -0.111003, 
    -0.0557982, 
    0.f, 
    0.0557982
  };

  //Cosine of fixed verticle angles in radians
  const double ELEVATION_ANGLES_COS_RAD_M8 [] = {
    0.949704634133,
    0.963983973086,
    0.976330009955,
    0.986386307388,
    0.993845490375,
    0.998443684292,
    1.0,
    0.998443684292
  };

  //Sine of fixed verticle angles in radians
  const double ELEVATION_ANGLES_SIN_RAD_M8 [] = {
    -0.313147102663,
    -0.2659603347,
    -0.216286180003,
    -0.164444679446,
    -0.110775183417,
    -0.0557692504572,
    0.0,
    0.0557692504572
  };

  #pragma pack(push, 1)
  //Structure to hold the Quanergy packet header
  struct M8_packet_header
  {
    uint32_t signature; // SIGNATURE
    uint32_t size;      // bytes
    uint32_t seconds;
    uint32_t nanoseconds;
    uint8_t  version_major;
    uint8_t  version_minor;
    uint8_t  version_patch;
    uint8_t  packet_type;
  }; //20 bytes

  //Structure to hold the Quanergy firing data
  struct M8_firing_data
  {
    uint16_t position;
    uint16_t padding;
    uint32_t returns_distances[M8_NUM_RETURNS][M8_NUM_LASERS];   // 10 um resolution in centimeters
    uint8_t  returns_intensities[M8_NUM_RETURNS][M8_NUM_LASERS]; // 255 indicates saturation
    uint8_t  returns_status[M8_NUM_LASERS];                      // 0 for now
  };

  //Structure that holds multiple sensor firings and gets sent in the TCP packet
  struct M8_data_packet
  {
    M8_firing_data data[M8_FIRING_PER_PKT];
    uint32_t seconds;     // seconds from Jan 1 1970
    uint32_t nanoseconds; // fractional seconds turned to nanoseconds
    uint16_t version;     // API version number.  Version 5 uses distance as units of 10 micrometers, <5 is 10mm
    uint16_t status;      // 0: good, 1: Sensor SW/FW mismatch
  }; //6612 bytes

  //Structure that holds both the header and data body portion of the Quanergy packet
  //Note: Includes only Quanergy "headers", doesn't include ethernet packet headers (port num, dest/src ip, etc)
  struct M8_complete_packet
  {
    //pcap_pkthdr pcap_header; //PCAP header/ethernet header
    M8_packet_header packet_header; //M8 packet header, 20 bytes, see M8 user guide page 22
    M8_data_packet data_body; //Data packet body, 6612 bytes, see M8 user guide page 22
  };

  #pragma pack(pop)

  const unsigned int BYTES_TO_SKIP_TO_M8_BODY = BYTES_TO_SKIP_TO_M8_HEADER + sizeof(M8_packet_header);

  /// convenience functions for deserialization of objects
  inline uint8_t deserialize(uint8_t net_char)
  {
    return net_char;
  }

  inline uint16_t deserialize(uint16_t net_short)
  {
    return ntohs(net_short);
  }

  inline uint32_t deserialize(uint32_t net_long)
  {
    return ntohl(net_long);
  }

  inline int8_t deserialize(int8_t net_char)
  {
    return net_char;
  }

  inline int16_t deserialize(int16_t net_short)
  {
    return ntohs(net_short);
  }

  inline int32_t deserialize(int32_t net_long)
  {
    return ntohl(net_long);
  }

//class M8_Packet_Header_object{
  /** \brief deserialize function for header */
  inline void deserialize(const char* network_buffer, M8_packet_header& object)
  {
    const M8_packet_header& network_order = *reinterpret_cast<const M8_packet_header*>(network_buffer);

    object.signature     = deserialize(network_order.signature);
    object.size          = deserialize(network_order.size);
    object.seconds       = deserialize(network_order.seconds);
    object.nanoseconds   = deserialize(network_order.nanoseconds);
    object.version_major = deserialize(network_order.version_major);
    object.version_minor = deserialize(network_order.version_minor);
    object.version_patch = deserialize(network_order.version_patch);
    object.packet_type   = deserialize(network_order.packet_type);
  }

  inline bool validateHeader(const M8_packet_header& object)
  {
    if (deserialize(object.signature) != M8_SIGNATURE)
    {
      cerr << "Invalid header signature: " << hex << showbase
                << object.signature << dec << noshowbase << endl;

      return false;
    }
    return true;
  }

  inline size_t getPacketSize(const M8_packet_header& object)
  {
    return deserialize(object.size);
  }
//};

//class M8_data_packet_object{
  inline void deserialize(const char* network_buffer, M8_firing_data& object)
  {
    const M8_firing_data& network_order = *reinterpret_cast<const M8_firing_data*>(network_buffer);

    object.position = deserialize(network_order.position);
    object.padding  = deserialize(network_order.padding);

    // deserialize each range
    const uint32_t* net_d_ptr = reinterpret_cast<const uint32_t*>(network_order.returns_distances);
    uint32_t* obj_d_ptr = reinterpret_cast<uint32_t*>(object.returns_distances);
    for_each(obj_d_ptr, obj_d_ptr + M8_NUM_RETURNS * M8_NUM_LASERS,
                  [&net_d_ptr](uint32_t& range)
                  {
                    range = deserialize(*net_d_ptr);
                    ++net_d_ptr;
                  });

    // deserialize each intensity
    const uint8_t* net_i_ptr = reinterpret_cast<const uint8_t*>(network_order.returns_intensities);
    uint8_t* obj_i_ptr = reinterpret_cast<uint8_t*>(object.returns_intensities);
    for_each(obj_i_ptr, obj_i_ptr + M8_NUM_RETURNS * M8_NUM_LASERS,
                  [&net_i_ptr](uint8_t& intensity)
                  {
                    intensity = deserialize(*net_i_ptr);
                    ++net_i_ptr;
                  });
    //TODO: possibly remove, extra clock cycles
    // deserialize each status
    const uint8_t* net_s_ptr = reinterpret_cast<const uint8_t*>(network_order.returns_status);
    uint8_t* obj_s_ptr = reinterpret_cast<uint8_t*>(object.returns_status);
    for_each(obj_s_ptr, obj_s_ptr + M8_NUM_LASERS,
                  [&net_s_ptr](uint8_t& status)
                  {
                    status = deserialize(*net_s_ptr);
                    ++net_s_ptr;
                  });
  }

  inline void deserialize(const char* network_buffer, M8_data_packet& object)
  {
    const M8_data_packet& network_order = *reinterpret_cast<const M8_data_packet*>(network_buffer);

    object.seconds      = deserialize(network_order.seconds);
    object.nanoseconds  = deserialize(network_order.nanoseconds);
    object.version      = deserialize(network_order.version);
    object.status       = deserialize(network_order.status);

    // deserialize each firing
    M8_firing_data* obj_d_ptr = reinterpret_cast<M8_firing_data*>(object.data);
    for_each(obj_d_ptr, obj_d_ptr + M8_FIRING_PER_PKT,
                  [&network_buffer](M8_firing_data& firing)
                  {
                    deserialize(network_buffer, firing);
                    network_buffer += sizeof(M8_firing_data);
                  });
  }

  inline void deserialize(const char* network_buffer, M8_complete_packet& object)
  {
    deserialize(network_buffer, object.packet_header);
    network_buffer += sizeof(M8_packet_header);
    deserialize(network_buffer, object.data_body);
  }

//};
} // namespace client

#endif
