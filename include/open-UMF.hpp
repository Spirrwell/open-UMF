/*
open-UMF:
	This is a library to generate a unique machine fingerprint across Windows, Linux, and Mac OS X.
	This project is licensed under the MIT license: https://opensource.org/licenses/MIT

	This library takes multiple bits of system information and generates hashes of that information.
	These hashes may be compared against each other and scored to see if the system indentification is similar enough to match.

	Library derived from ideas and code in this article: https://oroboro.com/unique-machine-fingerprint/

	Developed by Michael Barth (AKA Spirrwell): https://github.com/Spirrwell
*/


#ifndef OPEN_UMF_HPP
#define OPEN_UMF_HPP

#include <cstdint>
#include <string>

namespace OUMF
{
	using std::array;

	/* Identifiers used to generate a machine fingerprint. */
	enum
	{
		HASHID_CPU = 0,
		HASHID_VOLUME,
		HASHID_MAC1,
		HASHID_MAC2,
		HASHID_CHECKDIGITS,
		HASHID_MAX
	};

	/* This is a mask that will be used to obfuscate information. */
	typedef array< uint16_t, HASHID_MAX > HashMask;

	/* Example mask used to obfuscate machine information, you should probably use your own set of values. */
	// HashMask u16Mask = { 0x4e25, 0xf4a1, 0x5437, 0xab41, 0x0000 };

	/* Returns a string of hashes that uniquely identifies the system. Takes in a HashMask 'key' to obfuscate information. */
	std::string getSystemUniqueId( const HashMask &key );

	/* Compares unqiue system ID string against another, returns false if IDs are too dissimilar or on failure. */
	bool compareSystemUniqueId( const std::string &systemUID, const std::string &otherSystemUID, const HashMask &key );

	/* The functions below may be used to get machine information directly. */

	/* Get hashes for up to two mac addresses. These should be unique. */
	void getMacHash( uint16_t &mac1, uint16_t &mac2 );

	/* Obtain hash for primary system volume serial number. This should be unique. */
	uint16_t getVolumeHash();

	/* Obtain hash for CPU identification. This may not be unique. */
	uint16_t getCpuHash();

	/* Obtain the machine's system name. This may not be unique. */
	std::string getMachineName();
}

#endif // OPEN_UMF_HPP