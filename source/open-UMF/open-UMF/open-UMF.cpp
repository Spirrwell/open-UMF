#include "open-UMF.hpp"

#include <algorithm>
#include <array>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#include <IPHlpApi.h>
#endif // _WIN32

enum
{
	HASHID_MACHINENAME = 0,
	HASHID_CPU,
	HASHID_VOLUME,
	HASHID_MAC1,
	HASHID_MAC2,
	HASHID_CHECKDIGITS,
	HASHID_MAX
};

static const std::array< uint16_t, HASHID_MAX > s_u16Mask = { 0x6f90, 0x4e25, 0xf4a1, 0x5437, 0xab41, 0x0000 };

static void S_Smear( std::array< uint16_t, HASHID_MAX > &id )
{
	for ( size_t i = 0; i < id.size(); ++i )
	{
		for ( size_t j = i; j < id.size(); ++j )
		{
			if ( i != j )
				id[ i ] ^= id[ j ];
		}
	}

	for ( size_t i = 0; i < s_u16Mask.size(); ++i )
		id[ i ] ^= s_u16Mask[ i ];
}
static void S_UnSmear( std::array< uint16_t, HASHID_MAX > &id )
{
	for ( size_t i = 0; i < id.size(); ++i )
		id[ i ] ^= s_u16Mask[ i ];

	for ( size_t i = 0; i < s_u16Mask.size(); ++i )
	{
		for ( size_t j = 0; j < i; ++j )
		{
			if ( i != j )
				id[ HASHID_CHECKDIGITS - i ] ^= id[ HASHID_CHECKDIGITS - j ];
		}
	}
}

static const std::array< uint16_t, HASHID_MAX > &computeSystemUniqueId()
{
	static std::array< uint16_t, HASHID_MAX > id = {};
	static bool bComputed = false;

	if ( bComputed )
		return id;

	// Produce a number that uniquely identifies this system.
	id[ HASHID_MACHINENAME ] = getMachineNameHash();
	id[ HASHID_CPU ] = getCpuHash();
	id[ HASHID_VOLUME ] = getVolumeHash();
	getMacHash( id[ HASHID_MAC1 ], id[ HASHID_MAC2 ] );

	// Last block is some check-digits
	for ( size_t i = 0; i < HASHID_CHECKDIGITS; ++i )
		id[ HASHID_CHECKDIGITS ] += id[ i ];

	S_Smear( id );
	bComputed = true;

	return id;
}

std::string getSystemUniqueId()
{
	std::stringstream ss;

	const auto &id = computeSystemUniqueId();
	bool bLoopedOnce = false;

	for ( size_t i = 0; i < id.size(); ++i, bLoopedOnce = true )
	{
		if ( bLoopedOnce )
			ss << "-";

		std::array< char, 16 > num;
		std::snprintf( &num[ 0 ], num.size(), "%x", id[ i ] );

		switch ( std::strlen( &num[ 0 ] ) )
		{
			case 1:
				ss << "000";
				break;
			case 2:
				ss << "00";
				break;
			case 3:
				ss << "0";
				break;
			default:
				break;
		}

		ss << &num[ 0 ];
	}

	std::string systemUID = ss.str();
	std::transform( systemUID.begin(), systemUID.end(), systemUID.begin(), ::toupper );

	return systemUID;
}

bool unpackID( const std::string &systemUID, std::array< uint16_t, HASHID_MAX > &dstID )
{
	std::array< uint16_t, HASHID_MAX > id = {};
	size_t offset = 0;

	std::string uID = systemUID;
	const std::string delimiter = "-";

	// Unpack the given string. Parse failures return false.
	for ( size_t i = 0; i < id.size(); ++i )
	{
		offset = uID.find( delimiter );

		std::string testNum = "";

		if ( offset != std::string::npos )
		{
			testNum = uID.substr( 0, offset );
			uID.erase( 0, offset + delimiter.length() );
		}
		else
			testNum = uID;

		if ( testNum.empty() )
			return false;

		id[ i ] = static_cast< uint16_t >( std::stoi( testNum, nullptr, 16 ) );
	}

	S_UnSmear( id );

	// Make sure the ID is valid - by looking at check-digits
	uint16_t check = 0;
	for ( size_t i = 0; i < HASHID_CHECKDIGITS; ++i )
		check += id[ i ];

	if ( check != id[ HASHID_CHECKDIGITS ] )
		return false;

	dstID = id;

	return true;
}

bool validateSystemUniqueId( const std::string &systemUID, const std::string &otherSystemUID )
{
	std::array< uint16_t, HASHID_MAX > testID = {};
	std::array< uint16_t, HASHID_MAX > otherID = {};

	if ( !unpackID( systemUID, testID ) )
		return false;

	if ( !unpackID( otherSystemUID, otherID ) )
		return false;

	uint32_t score = 0;

	for ( size_t i = 0; i < testID.size() - 1; ++i )
	{
		if ( testID[ i ]  == otherID[ i ] )
			++score;
	}

	// If we score 3 points or more, then the ID matches
	return ( score >= 3 ) ? true : false;
}

#ifdef _WIN32
uint16_t hashMacAddress( const PIP_ADAPTER_INFO &info )
{
	uint16_t hash = 0;
	for ( uint32_t i = 0; i < info->AddressLength; ++i )
		hash += ( info->Address[ i ] << ( ( i & 1 ) * 8 ) );

	return hash;
}

void getMacHash( uint16_t &mac1, uint16_t &mac2 )
{
	IP_ADAPTER_INFO AdapterInfo[ 32 ];
	DWORD dwBufLen = sizeof( AdapterInfo );
	DWORD dwStatus = GetAdaptersInfo( AdapterInfo, &dwBufLen );

	if ( dwStatus != ERROR_SUCCESS )
		return;

	PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
	mac1 = hashMacAddress( pAdapterInfo );

	if ( pAdapterInfo->Next )
		mac2 = hashMacAddress( pAdapterInfo->Next );

	// Sort the Mac addresses.
	// We don't want to invalidate both Mac addresses if they just change order.
	if ( mac1 > mac2 )
		std::swap( mac1, mac2 );
}

uint16_t getVolumeHash()
{
	// NOTE: This doesn't account for more than 26 HDDs
	std::array< char, 3 > driveLetter;
	GetSystemWindowsDirectory( &driveLetter[ 0 ], driveLetter.size() );

	DWORD serialNum = 0;
	GetVolumeInformation( &driveLetter[ 0 ], nullptr, 0, &serialNum, nullptr, nullptr, nullptr, 0 );

	uint16_t hash = ( uint16_t )( ( serialNum + ( serialNum >> 16 ) ) & 0xFFFF );
	return hash;
}

uint16_t getMachineNameHash()
{
	std::string machineName = getMachineName();
	uint16_t hash = 0;
	
	for ( size_t i = 0; i < machineName.size(); ++i )
		hash += static_cast< uint16_t >( machineName[ i ] );

	return hash;
}

uint16_t getCpuHash()
{
	int cpuinfo[ 4 ] = { 0, 0, 0, 0 };
	__cpuid( cpuinfo, 0 );

	uint16_t hash = 0;
	uint16_t *pCpuInfo = ( uint16_t* )( &cpuinfo[ 0 ] );

	for ( uint32_t i = 0; i < 8; ++i )
		hash += pCpuInfo[ i ];

	return hash;
}

std::string getMachineName()
{
	std::string computerName( 1024, '\0' );
	DWORD size = 1024;

	GetComputerName( &computerName[ 0 ], &size );
	return computerName;
}

#endif // _WIN32