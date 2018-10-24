#include "open-UMF.hpp"

#include <algorithm>
#include <array>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#include <IPHlpApi.h>
#endif // _WIN32

struct systeminfo_t
{
	std::string machineName;
	std::array< uint16_t, 5 > systemUID;
};

static const std::array< uint16_t, 5 > s_u16Mask = { 0x4e25, 0xf4a1, 0x5437, 0xab41, 0x0000 };

static void S_Smear( std::array< uint16_t, 5 > &id )
{
	for ( size_t i = 0; i < id.size(); ++i )
	{
		for ( size_t j = i; j < id.size(); ++j )
		{
			if ( i != j )
				id[ i ] ^= id[ j ];
		}

		for ( size_t i = 0; i < s_u16Mask.size(); ++i )
			id[ i ] ^= s_u16Mask[ i ];
	}
}
static void S_UnSmear( std::array< uint16_t, 5 > &id )
{
	for ( size_t i = 0; i < id.size(); ++i )
		id[ i ] ^= s_u16Mask[ i ];

	for ( size_t i = 0; i < s_u16Mask.size(); ++i )
	{
		for ( size_t j = 0; j < i; ++j )
		{
			if ( i != j )
				id[ 4 - 1 ] ^= id[ 4 - j ];
		}
	}
}

static const std::array< uint16_t, 5 > &computeSystemUniqueId()
{
	static std::array< uint16_t, 5 > id = {};
	static bool bComputed = false;

	if ( bComputed )
		return id;

	// Produce a number that uniquely identifies this system.
	id[ 0 ] = getCpuHash();
	id[ 1 ] = getVolumeHash();
	getMacHash( id[ 2 ], id[ 3 ] );

	// Last block is some check-digits
	for ( uint32_t i = 0; i < id.size() - 1; ++i )
		id[ id.size() - 1 ] += id[ i ];

	S_Smear( id );
	bComputed = true;

	return id;
}

std::string getSystemUniqueId()
{
	std::stringstream ss;
	ss << getMachineName().c_str(); // TODO: Figure out why this breaks if it's not a C string

	const auto &id = computeSystemUniqueId();
	for ( size_t i = 0; i < id.size(); ++i )
	{
		std::array< char, 16 > num;
		std::snprintf( &num[ 0 ], num.size(), "%x", id[ i ] );

		ss << "-";

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

bool unpackID( const std::string &systemUID, systeminfo_t &dstInfo )
{
	std::array< uint16_t, 5 > id = {};

	// Unpack the given string. Parse failures return false.
	size_t offset = systemUID.find( "-" );
	std::string machineName = systemUID.substr( 0, offset );
	if ( machineName.empty() )
		return false;

	for ( size_t i = 0; i < id.size(); ++i )
	{
		std::string testNum = systemUID.substr( offset, offset = systemUID.find( "-", offset ) );

		if ( testNum.empty() )
			return false;

		id[ i ] = static_cast< uint16_t >( std::stoi( testNum, nullptr, 16 ) );
	}

	S_UnSmear( id );

	// Make sure the ID is valid - by looking at check-digits
	uint16_t check = 0;
	for ( uint32_t i = 0; i < id.size() - 1; ++i )
		check += id[ i ];

	if ( check != id[ id.size() - 1 ] )
		return false;

	dstInfo.machineName = machineName;
	dstInfo.systemUID = id;

	return true;
}

bool validateSystemUniqueId( const std::string &systemUID, const std::string &otherSystemUID )
{
	systeminfo_t testInfo = {};
	systeminfo_t otherInfo = {};

	if ( !unpackID( systemUID, testInfo ) )
		return false;

	if ( !unpackID( otherSystemUID, otherInfo ) )
		return false;

	uint32_t score = 0;

	for ( size_t i = 0; i < testInfo.systemUID.size() - 1; ++i )
	{
		if ( testInfo.systemUID[ i ]  == otherInfo.systemUID[ i ] )
			++score;
	}

	if ( testInfo.machineName == otherInfo.machineName )
		++score;

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