/*
open-UMF:
	This is a library to generate a unique machine fingerprint across Windows, Linux, and Mac OS X.
	This project is licensed under the MIT license: https://opensource.org/licenses/MIT

	This library takes multiple bits of system information and generates hashes of that information.
	These hashes may be compared against each other and scored to see if the system indentification is similar enough to match.

	Library derived from ideas and code in this article: https://oroboro.com/unique-machine-fingerprint/

	Developed by Michael Barth (AKA Spirrwell): https://github.com/Spirrwell
*/

#include "open-UMF.hpp"

#include <algorithm>
#include <sstream>

#ifdef _WIN32
#include <Windows.h>
#include <intrin.h>
#include <IPHlpApi.h>
#endif // _WIN32

namespace OUMF
{
	/* Hash IDs will be the same size as HashMasks, but are really two different things */
	typedef array< uint16_t, HASHID_MAX > HashID;

	/* Obfuscates machine information 'id' using the 'key' array */
	static void S_Smear( HashID &id, const HashMask &key )
	{
		for ( size_t i = 0; i < id.size(); ++i )
		{
			for ( size_t j = i; j < id.size(); ++j )
			{
				if ( i != j )
					id[ i ] ^= id[ j ];
			}
		}

		for ( size_t i = 0; i < key.size(); ++i )
			id[ i ] ^= key[ i ];
	}

	/* Clears obfuscation and reverts machine information 'id' back to their original hashes or 'HashID' */
	static void S_UnSmear( HashID &id, const HashMask &key )
	{
		for ( size_t i = 0; i < id.size(); ++i )
			id[ i ] ^= key[ i ];

		for ( size_t i = 0; i < id.size(); ++i )
		{
			for ( size_t j = 0; j < i; ++j )
			{
				if ( i != j )
					id[ HASHID_CHECKDIGITS - i ] ^= id[ HASHID_CHECKDIGITS - j ];
			}
		}
	}

	/* Obfuscates a string with the HashMask 'key' */
	static void S_SmearString( std::string &str, const HashMask &key ) // TODO: Templatize this so we can obfuscate with anything
	{
		for ( size_t i = 0; i < str.size(); ++i )
		{
			for ( size_t j = i; j < str.size(); ++j )
			{
				if ( i != j )
					str[ i ] ^= str[ j ];
			}
		}

		size_t charactersLeft = str.size();
		size_t charactersRead = 0;

		while ( charactersLeft >= key.size() )
		{
			for ( size_t i = 0; i < key.size(); ++i )
			{
				str[ i + charactersRead ] ^= key[ i ];
				--charactersLeft;
			}

			charactersRead += key.size();
		}

		if ( charactersLeft > 0 )
		{
			for( size_t i = 0; i < charactersLeft; ++i )
				str[ i + charactersRead ] ^= key[ i ];

			charactersRead += charactersLeft;
			charactersLeft = 0;
		}
	}

	/* Clears string obfuscation with the HashMask 'key' */
	static void S_UnsmearString( std::string &str, const HashMask &key ) // TODO: Templatize this so we can obfuscate with anything
	{
		size_t unalignedChars = str.size() % key.size();

		for( size_t i = 0; i < unalignedChars; ++i )
			str[ str.size() - unalignedChars + i ] ^= key[ i ];

		size_t charactersRead = 0;
		size_t charactersLeft = str.size();

		while( charactersLeft >= key.size() )
		{
			for ( size_t i = 0; i < key.size(); ++i )
			{
				str[ i + charactersRead ] ^= key[ i ];
				--charactersLeft;
			}

			charactersRead += key.size();
		}

		for ( size_t i = 0; i < str.size(); ++i )
		{
			for ( size_t j = 0; j < i; ++j )
			{
				if ( i != j )
					str[ str.size() - 1 - i ] ^= str[ str.size() - 1 - j ];
			}
		}
	}

	/* Computes a unique system ID from machine name, cpu ID, Mac addresses, and primary volume serial */
	static const HashMask &computeSystemUniqueId( const HashMask &key )
	{
		static HashMask id = {};
		static bool bComputed = false;

		if ( bComputed )
			return id;

		// Produce a number that uniquely identifies this system.
		id[ HASHID_CPU ] = getCpuHash();
		id[ HASHID_VOLUME ] = getVolumeHash();
		getMacHash( id[ HASHID_MAC1 ], id[ HASHID_MAC2 ] );

		// Last block is some check-digits
		for ( size_t i = 0; i < HASHID_CHECKDIGITS; ++i )
			id[ HASHID_CHECKDIGITS ] += id[ i ];

		S_Smear( id, key );
		bComputed = true;

		return id;
	}

	/* Returns a string of hashes that uniquely identifies the system. Takes in a HashMask 'key' to obfuscate information */
	std::string getSystemUniqueId( const HashMask &key )
	{
		std::stringstream ss;

		const auto &id = computeSystemUniqueId( key );
		bool bLoopedOnce = false;

		for ( size_t i = 0; i < id.size(); ++i, bLoopedOnce = true )
		{
			if ( bLoopedOnce )
				ss << "-";

			array< char, 16 > num;
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

	/* Takes a machine identifier string and unpacks into the original hashes */
	static bool unpackID( const std::string &systemUID, HashMask &dstID, const HashMask &key )
	{
		HashMask id = {};

		// Unpack the given string. Parse failures return false.
		auto parseString = [ & ]()
		{
			std::string UID = systemUID;
			constexpr const static char delimiter = '-';

			for ( size_t i = 0; i < id.size(); ++i )
			{
				size_t offset = UID.find( delimiter );

				std::string testNum = "";

				if ( offset != std::string::npos )
				{
					testNum = UID.substr( 0, offset );
					UID.erase( 0, offset + sizeof( delimiter ) );
				}
				else
					testNum = UID;

				if ( testNum.empty() )
					return false;

				id[ i ] = static_cast< uint16_t >( std::stoi( testNum, nullptr, 16 ) );
			}

			return true;
		};

		if ( !parseString() )
			return false;

		S_UnSmear( id, key );

		// Make sure the ID is valid - by looking at check-digits
		uint16_t check = 0;
		for ( size_t i = 0; i < HASHID_CHECKDIGITS; ++i )
			check += id[ i ];

		if ( check != id[ HASHID_CHECKDIGITS ] )
			return false;

		dstID = id;

		return true;
	}

	/* Compares unqiue system ID string against another, returns false if IDs are too dissimilar or on failure */
	bool compareSystemUniqueId( const std::string &systemUID, const std::string &otherSystemUID, const HashMask &key )
	{
		HashMask testID = {};
		HashMask otherID = {};

		if ( !unpackID( systemUID, testID, key ) )
			return false;

		if ( !unpackID( otherSystemUID, otherID, key ) )
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
		array< char, 3 > driveLetter;
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
}

#endif // _WIN32