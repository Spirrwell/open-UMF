#ifndef OPEN_UMF_HPP
#define OPEN_UMF_HPP

#include <cstdint>
#include <string>

std::string getSystemUniqueId();
bool validateSystemUniqueId( const std::string &systemUID, const std::string &otherSystemUID );
void getMacHash( uint16_t &mac1, uint16_t &mac2 );
uint16_t getVolumeHash();
uint16_t getCpuHash();
std::string getMachineName();

#endif // OPEN_UMF_HPP