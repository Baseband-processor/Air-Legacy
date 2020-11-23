#if !defined(AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_)
#define AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_

#ifdef _MSC_VER
// This disables a VS warning for zero-sized arrays.
#pragma warning( disable : 4200)
#endif 

#ifdef __cplusplus
extern "C" {
#endif

#define AIRPCAP_ERRBUF_SIZE 512
#include "airpcap-types.h"

/*!
	\mainpage AirPcap interface documentation
	
	\section Introduction
	This document describes the data structures and the functions exported by the CACE Technologies AirPcap library.
	The AirPcap library provides low-level access to the AirPcap devices including advanced capabilities such as channel setting,
	link type control and WEP configuration.<br>
	This manual includes the following sections:
	- \ref airpcapfuncs
	- \ref airpcapdefs
	- \ref radiotap
	\note Throughout this documentation, \e device refers to a physical AirPcap device, while \e adapter is an open API
	instance. Most of the AirPcap API operations are adapter-specific but some of them, like setting the channel, are
	per-device and will be reflected on all the open adapters. These functions will have "Device" in their name, e.g.
	AirpcapSetDeviceChannel().
*/

/** @defgroup airpcapdefs AirPcap definitions and data structures
 *  @{
 */

/*!
  \brief This string is the fixed prefix in the airpcap adapter name. 
  It can be used to parse the name field in an AirpcapDeviceDescription structure.
*/
#define AIRPCAP_DEVICE_NAME_PREFIX		"\\\\.\\airpcap"

/*!
  \brief This string is the scanf modifier to extract the adapter number from an adapter name. 
  It can be used to parse the name field in an AirpcapDeviceDescription structure with scanf.
*/
#define AIRPCAP_DEVICE_NUMBER_EXTRACT_STRING		 "\\\\.\\airpcap%u"

/*!
  \brief Entry in the list returned by \ref AirpcapGetDeviceList().
*/
typedef struct _AirpcapDeviceDescription
{
	struct	_AirpcapDeviceDescription *next;			///< Next element in the list
	PCHAR	Name;										///< Device name
	PCHAR	Description;								///< Device description
} AirpcapDeviceDescription, *PAirpcapDeviceDescription;

#define MAX_ENCRYPTION_KEYS 64

#define WEP_KEY_MAX_SIZE 32		///< Maximum size of a WEP key, in bytes. This is the size of an entry in the 
								///< AirpcapWepKeysCollection structure

#ifndef __GNUC__
#pragma pack(push)
#pragma pack(1)
#endif // __GNUC__


#define AIRPCAP_KEYTYPE_WEP		0	///< Key type: WEP. The key can have an arbitrary length smaller than 32 bytes.
#define AIRPCAP_KEYTYPE_TKIP	1	///< Key type: TKIP (WPA). NOT SUPPORTED YET.
#define AIRPCAP_KEYTYPE_CCMP	2	///< Key type: CCMP (WPA2). NOT SUPPORTED YET.

/*!
  \brief WEP key container
*/
typedef struct _AirpcapKey
{
	UINT KeyType;						///< Type of key, can be on of: \ref AIRPCAP_KEYTYPE_WEP, \ref AIRPCAP_KEYTYPE_TKIP, \ref AIRPCAP_KEYTYPE_CCMP. Only AIRPCAP_KEYTYPE_WEP is supported by the driver at the moment.
	UINT KeyLen;						///< Length of the key, in bytes
	BYTE KeyData[WEP_KEY_MAX_SIZE];		///< Key Data
}
#ifdef __GNUC__
__attribute__((__packed__))
#endif // __GNUC__
AirpcapKey, *PAirpcapKey;

/*!
  \brief frequency Band.
   802.11 adapters can support different frequency bands, the most important of which are: 2.4GHz (802.11b/g/n) 
   and 5GHz (802.11a/n).
*/
typedef enum _AirpcapChannelBand
{
    AIRPCAP_CB_AUTO = 1,				///< Automatically pick the best frequency band
    AIRPCAP_CB_2_4_GHZ = 2,				///< 2.4 GHz frequency band
    AIRPCAP_CB_4_GHZ = 4,				///< 4 GHz frequency band
    AIRPCAP_CB_5_GHZ = 5				///< 5 GHz frequency band
}AirpcapChannelBand, *PAirpcapChannelBand;

/*!
  \brief Type of frame validation the adapter performs.
   An adapter can be instructed to accept different kind of frames: correct frames only, frames with wrong Frame Check Sequence (FCS) only, all frames.
*/
typedef enum _AirpcapValidationType
{
    AIRPCAP_VT_ACCEPT_EVERYTHING = 1,		///< Accept all the frames the device captures
    AIRPCAP_VT_ACCEPT_CORRECT_FRAMES = 2,	///< Accept correct frames only, i.e. frames with correct Frame Check Sequence (FCS).
    AIRPCAP_VT_ACCEPT_CORRUPT_FRAMES = 3,	///< Accept corrupt frames only, i.e. frames with worng Frame Check Sequence (FCS).
	AIRPCAP_VT_UNKNOWN = 4					///< Unknown validation type. You should see it only in case of error.
}AirpcapValidationType, *PAirpcapValidationType;

/*!
  \brief Type of decryption the adapter performs.
   An adapter can be instructed to turn decryption (based on the device-configured keys configured 
   with \ref AirpcapSetDeviceKeys()) on or off.
*/
typedef enum _AirpcapDecryptionState
{
    AIRPCAP_DECRYPTION_ON = 1,				///< This adapter performs decryption
    AIRPCAP_DECRYPTION_OFF = 2				///< This adapter does not perform decryption
}AirpcapDecryptionState, *PAirpcapDecryptionState;

#define AIRPCAP_MEDIUM_802_11_A		1	///< 802.11a medium.
#define AIRPCAP_MEDIUM_802_11_B		2	///< 802.11b medium.
#define AIRPCAP_MEDIUM_802_11_G		4	///< 802.11g medium.
#define AIRPCAP_MEDIUM_802_11_N		8	///< 802.11n medium.

#define AIRPCAP_BAND_2GHZ			1	///< 2.4 GHz band.
#define AIRPCAP_BAND_5GHZ			2	///< 5 GHz band.

typedef enum _AirpcapAdapterBus
{
	AIRPCAP_BUS_USB,
	AIRPCAP_BUS_PCI,
	AIRPCAP_BUS_PCI_EXPRESS,
	AIRPCAP_BUS_MINI_PCI,
	AIRPCAP_BUS_MINI_PCI_EXPRESS,
	AIRPCAP_BUS_CARDBUS,
	AIRPCAP_BUS_EXPRESSCARD
}AirpcapAdapterBus;

typedef enum _AirpcapAdapterId
{
	AIRPCAP_ID_CLASSIC,
	AIRPCAP_ID_CLASSIC_REL2,
	AIRPCAP_ID_TX,
	AIRPCAP_ID_EX,
	AIRPCAP_ID_N,
	AIRPCAP_ID_NX
}AirpcapAdapterId;

/*!
  \brief Storage for a MAC address
*/
typedef struct _AirpcapMacAddress
{
	BYTE Address[6];		///< MAC address bytes
}
#ifdef __GNUC__
__attribute__((__packed__))
#endif // __GNUC__
	AirpcapMacAddress, *PAirpcapMacAddress;

/*!
  \brief This structure is used to store a collection of WEP keys. 
  Note that the definition of the structure doesn't contain any key, so be careful to allocate a buffer
  with the size of the key, like in the following example:
  \code
	PAirpcapKeysCollection KeysCollection;
	UINT KeysCollectionSize;
	
	KeysCollectionSize = sizeof(AirpcapKeysCollection) + NumKeys * sizeof(AirpcapKey);
	
	KeysCollection = (PAirpcapKeysCollection)malloc(KeysCollectionSize);
	if(!KeysCollection)
	{
		// Error
	}
  \endcode
*/
typedef struct _AirpcapKeysCollection
{
	UINT nKeys;												///< Number of keys in the collection
	AirpcapKey Keys[0];										///< Array of nKeys keys. 
} AirpcapKeysCollection, *PAirpcapKeysCollection;

/*!
  \brief Packet header.
  This structure defines the BPF that preceeds every packet delivered to the application.
*/
typedef struct _AirpcapBpfHeader 
{
	UINT TsSec;			///< Timestamp associated with the captured packet. SECONDS.
	UINT TsUsec;		///< Timestamp associated with the captured packet. MICROSECONDS.
	UINT Caplen;		///< Length of captured portion. The captured portion <b>can be different</b> from the original packet, because it is possible (with a proper filter) to instruct the driver to capture only a portion of the packets.
	UINT Originallen;	///< Original length of packet
	USHORT	Hdrlen;		///< Length of bpf header (this struct plus alignment padding). In some cases, a padding could be added between the end of this structure and the packet data for performance reasons. This field can be used to retrieve the actual data of the packet.
}
#ifdef __GNUC__
__attribute__((__packed__))
#endif // __GNUC__
AirpcapBpfHeader, *PAirpcapBpfHeader;

/*!
  \brief Structure used to read the free running counter on a device.
  This structure contains the current value of the counter used by the device to timestamp packets (when the hardware supports hardware timestamps). 
  This structure also contains the value of the software counter (used to timestamp packets in software), before and after the hardware counter is read
  on the device.
*/
typedef struct _AirpcapDeviceTimestamp
{
	ULONGLONG	DeviceTimestamp;			///< Current value of the device counter, in microseconds.
	ULONGLONG	SoftwareTimestampBefore; ///< Value of the software counter used to timestamp packets before reading the device counter, in microseconds.
	ULONGLONG	SoftwareTimestampAfter;	///< Value of the software counter used to timestamp packets after reading the device counter, in microseconds.
}
#ifdef __GNUC__
__attribute__((__packed__))
#endif // __GNUC__
	AirpcapDeviceTimestamp, *PAirpcapDeviceTimestamp;


/// Helper macros to extract packets coming from the driver. Rounds up to the next even multiple of AIRPCAP_ALIGNMENT. 
#define AIRPCAP_ALIGNMENT sizeof(int)
#define AIRPCAP_WORDALIGN(x) (((x)+(AIRPCAP_ALIGNMENT-1))&~(AIRPCAP_ALIGNMENT-1))

#ifndef __GNUC__
#pragma pack(pop)
#endif // __GNUC__

#define AIRPCAP_ERRBUF_SIZE 512		///< Size of the error buffer, in bytes

/*!
  \brief Channel info flag: the channel is enabled for transmission, too.
  To comply with the electomagnetic emission regulations of the different countries, the AirPcap hardware can be programmed
  to block transmission on specific channels. This flag is set by AirpcapGetDeviceSupportedChannels() to indicate that a 
  channel in the list supports transmission.
*/
#define AIRPCAP_CIF_TX_ENABLED	0x1
	

/*!
  \brief Channel information.
  Used by \ref AirpcapSetDeviceChannelEx(), \ref AirpcapGetDeviceChannelEx(), \ref AirpcapGetDeviceSupportedChannels()
*/
typedef struct _AirpcapChannelInfo
{
	UINT Frequency;		///< Channel frequency, in MHz.
	/*! 
		\brief 802.11n specific. Offset of the extension channel in case of 40MHz channels. 
		
		Possible values are -1, 0 +1: 
		- -1 means that the extension channel should be below the control channel (e.g. Control = 5 and Extension = 1)
		- 0 means that no extension channel should be used (20MHz channels or legacy mode)
		- +1 means that the extension channel should be above the control channel (e.g. Control = 1 and Extension = 5)
		  
		In case of 802.11a/b/g channels (802.11n legacy mode), this field should be set to 0.
	*/
	CHAR ExtChannel;
	UCHAR Flags;		///< Channel Flags. The only flag supported at this time is \ref AIRPCAP_CIF_TX_ENABLED.
	UCHAR Reserved[2];	///< Reserved. It should be set to {0,0}.
	struct AirpcapAdapterChannelInfoPrivate *_Private; ///< Reserved.
}
AirpcapChannelInfo, *PAirpcapChannelInfo;

/*!
  \brief Link type. 
  
   AirPcap supports three 802.11 link types: 
   - plain 802.11 (\ref AIRPCAP_LT_802_11)
   - a radiotap header is prepended to each packet (\ref AIRPCAP_LT_802_11_PLUS_RADIO)
   - a PPI header is prepended to each packet (\ref AIRPCAP_LT_802_11_PLUS_PPI).
*/
typedef enum _AirpcapLinkType 
{
    AIRPCAP_LT_802_11 = 1,				///< plain 802.11 link type. Every packet in the buffer contains the raw 802.11 frame, including MAC FCS.
    AIRPCAP_LT_802_11_PLUS_RADIO = 2,	///< 802.11 plus radiotap link type. Every packet in the buffer contains a radiotap header followed by the 802.11 frame. MAC FCS is included.
	AIRPCAP_LT_UNKNOWN = 3,				///< Unknown link type. You should see it only in case of error.
	AIRPCAP_LT_802_11_PLUS_PPI = 4		///< 802.11 plus PPI header link type. Every packet in the buffer contains a PPI header followed by the 802.11 frame. MAC FCS is included.
}AirpcapLinkType, *PAirpcapLinkType;

#ifndef __AIRPCAP_DRIVER__

#if !defined(AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_)
#define AIRPCAP_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_
/*!
  \brief Adapter handle.
*/
typedef struct _AirpcapHandle AirpcapHandle, *PAirpcapHandle;
#endif

/*!
  \brief Capture statistics.
   Returned by \ref AirpcapGetStats().
*/
typedef struct _AirpcapStats 
{
	UINT Recvs;			///< Number of packets that the driver received by the adapter 
						///< from the beginning of the current capture. This value includes the packets 
						///< dropped because of buffer full.
	UINT Drops;			///< number of packets that the driver dropped from the beginning of a capture. 
						///< A packet is lost when the the buffer of the driver is full. 
	UINT IfDrops;		///< Packets dropped by the card before going to the USB bus. 
						///< Not supported at the moment.
	UINT Capt;			///< number of packets that pass the BPF filter, find place in the kernel buffer and
						///< therefore reach the application.
}AirpcapStats, *PAirpcapStats;

/*!
  \brief Device capabilities.
   Returned by \ref AirpcapGetDeviceCapabilities().
*/
typedef struct _AirpcapDeviceCapabilities 
{
	AirpcapAdapterId AdapterId;		///< An Id that identifies the adapter model.
	CHAR* AdapterModelName;			///< String containing a printable adapter model.
	AirpcapAdapterBus AdapterBus;	///< The type of bus the adapter is plugged to.
	BOOL CanTransmit;				///< TRUE if the adapter is able to perform frame injection.
	BOOL CanSetTransmitPower;		///< TRUE if the adapter's transmit power is can be specified by the user application.
	BOOL ExternalAntennaPlug;		///< TRUE if the adapter supports plugging one or more external antennas.
	UINT SupportedMedia;			///< An OR combination of the media that the device supports. Possible values are: \ref AIRPCAP_MEDIUM_802_11_A,
									///< \ref AIRPCAP_MEDIUM_802_11_B, \ref AIRPCAP_MEDIUM_802_11_G or \ref AIRPCAP_MEDIUM_802_11_N.
									///< Not supported at the moment.
	UINT SupportedBands;			///< An OR combination of the bands that the device supports. Can be one of: \ref AIRPCAP_BAND_2GHZ, 
									///< \ref AIRPCAP_BAND_5GHZ.
}AirpcapDeviceCapabilities, *PAirpcapDeviceCapabilities;

// MAC flags
#define AIRPCAP_MF_MONITOR_MODE_ON		1	///< If set, the device is configured to work in monitor mode.
											///< When monitor mode is on, the device captures all the frames transmitted on the channel. This includes:
											///<    - unicast packets
											///<    - multicast packets
											///<    - broadcast packets
											///<    - control and management packets
											///<
											///< When monitor mode is off, the device has a filter on unicast packets to capture only the packets whose MAC
											///< destination address equals the device's address. This means the following frames will be received:
											///<   - unicast packets whose destination is the address of the device
											///<   - multicast packets
											///<   - broadcast packets
											///<   - beacons and probe requests

#define AIRPCAP_MF_ACK_FRAMES_ON		2	///< If set, the device will acknowledge the data frames sent to its address. This is useful when the device needs to interact with other devices on the 
											///< 802.11 network, bacause handling the ACKs in software is normally too slow.

/*@}*/

/** @defgroup airpcapfuncs AirPcap functions
 *  @{
 */

/*!
  \brief Returns a string with the API version
  \param VersionMajor Pointer to a variable that will be filled with the major version number.
  \param VersionMinor Pointer to a variable that will be filled with the minor version number.
  \param VersionRev Pointer to a variable that will be filled with the revision number.
  \param VersionBuild Pointer to a variable that will be filled with the build number.
*/
void AirpcapGetVersion(PUINT VersionMajor, PUINT VersionMinor, PUINT VersionRev, PUINT VersionBuild);

/*!
  \brief Returns the last error related to the specified handle
  \param AdapterHandle Handle to an open adapter.
  \return The string with the last error.
*/
PCHAR AirpcapGetLastError(PAirpcapHandle AdapterHandle);

/*! 
  \brief Returns the list of available devices 
  \param PPAllDevs Address to a caller allocated pointer. On success this pointer will receive the head of a list of available devices.
  \param Ebuf String that will contain error information if FALSE is returned. The size of the string must be AIRPCAP_ERRBUF_SIZE bytes.
  \return TRUE on success. FALSE is returned on failure, in which case Ebuf is filled in with an appropriate error message.
  
	Here's a snippet of code that shows how to use AirpcapGetDeviceList():
	\code
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	AirpcapDeviceDescription *Desc, *tDesc;
	if(AirpcapGetDeviceList(&Desc, Ebuf) == -1)
	{
		printf("Unable to get the list of devices: %s\n", Ebuf);
		return -1;
	}
	
	for(tDesc = Desc; tDesc; tDesc = tDesc->next)
	{
		printf("%u) %s (%s)\n",
		++i,
		tDesc->Name,
		tDesc->Description);
	}
  	AirpcapFreeDeviceList(Desc);
	\endcode
*/
BOOL AirpcapGetDeviceList(PAirpcapDeviceDescription *PPAllDevs, PCHAR Ebuf);

/*!
  \brief Frees a list of devices returned by AirpcapGetDeviceList()
  \param PAllDevs Head of the list of devices returned by \ref AirpcapGetDeviceList().
*/
VOID AirpcapFreeDeviceList(PAirpcapDeviceDescription PAllDevs);

/*!
  \brief Opens an adapter
  \param DeviceName Name of the device to open. Use \ref AirpcapGetDeviceList() to get the list of devices.
  \param Ebuf String that will contain error information in case of failure. The size of the string must be AIRPCAP_ERRBUF_SIZE bytes.
  \return A PAirpcapHandle handle on success. NULL is returned on failure, in which case Ebuf is filled in with an appropriate error message.
*/
PAirpcapHandle AirpcapOpen(PCHAR DeviceName, PCHAR Ebuf);

/*!
  \brief Closes an adapter
  \param AdapterHandle Handle to the adapter to close.
*/
VOID AirpcapClose(PAirpcapHandle AdapterHandle);

/*!
  \brief Get the capabilties of a device.
  \param AdapterHandle Handle to the adapter.
  \param PCapabilities Pointer to a library-allocated \ref AirpcapDeviceCapabilities structure that contains the capabilities of the adapter.
  \return TRUE on success.
  \note The PCapabilities structure returned by \ref AirpcapGetDeviceCapabilities() must be considered invalid 
  after the adapter has been closed. 
*/
BOOL AirpcapGetDeviceCapabilities(PAirpcapHandle AdapterHandle, PAirpcapDeviceCapabilities *PCapabilities);

/*!
  \brief Sets the device's monitor mode and acknowledgment settings.
  \param AdapterHandle Handle to the adapter.
  \param AirpcapMacFlags Flags word, that contains a bitwise-OR combination of the following flags: \ref AIRPCAP_MF_MONITOR_MODE_ON and \ref AIRPCAP_MF_ACK_FRAMES_ON .
  \return TRUE on success.
  When an adapter is plugged into the system, it's always configured with monitor mode ON and acknowledgment settings OFF.
		These values are not stored persistently, so if you want to turn monitor mode off, you will need to do it 
		every time you attach the adapter.
  \note currently, the AirPcap adapter supports frames acknowleging when the adapter is NOT in monitor mode. This means that
        the combinations in which the two flags have the same value will cause AirpcapSetDeviceMacFlags() to fail.
*/
BOOL AirpcapSetDeviceMacFlags(PAirpcapHandle AdapterHandle, UINT AirpcapMacFlags);

/*!
  \brief Gets the device's monitor mode and acknowledgement settings.
  \param AdapterHandle Handle to the adapter.
  \param PAirpcapMacFlags User-provided flags word, that will be filled by the function with an OR combination of the 
         following flags: \ref AIRPCAP_MF_MONITOR_MODE_ON and \ref AIRPCAP_MF_ACK_FRAMES_ON.
  \return TRUE on success.
  When an adapter is plugged into the system, it's always configured with monitor mode ON and acknowledgment settings OFF.
		These values are not stored persistently, so if you want to turn monitor mode off, you will need to do it 
		every time you attach the adapter.
*/
BOOL AirpcapGetDeviceMacFlags(PAirpcapHandle AdapterHandle, PUINT PAirpcapMacFlags);

/*!
  \brief Sets the link type of an adapter
  \param AdapterHandle Handle to the adapter.
  \param NewLinkType the "link type", i.e. the format of the frames that will be received from the adapter.
  \return TRUE on success.
  the "link type" determines how the driver will encode the packets captured from the network.
  Aircap supports two link types:
  - \ref AIRPCAP_LT_802_11, to capture 802.11 frames (including control frames) without any
   power information. Look at the "Capture_no_radio" example application in the developer's pack 
   for a reference on how to decode 802.11 frames with this link type.
  - \ref AIRPCAP_LT_802_11_PLUS_RADIO, to capture 802.11 frames (including control frames) with a radiotap header
  that contains power and channel information. More information about the radiotap header can be found in the
  \ref radiotap section. Moreover, the "Capture_radio" example application in 
  the developer's pack can be used as a reference on how to decode 802.11 frames with radiotap headers.
  - \ref AIRPCAP_LT_802_11_PLUS_PPI, to capture 802.11 frames (including control frames) with a Per Packet Information (PPI)
	header that contains per-packet meta information like channel and power information. More details on the PPI header can
	be found in the PPI online documentation (TODO).
*/
BOOL AirpcapSetLinkType(PAirpcapHandle AdapterHandle, AirpcapLinkType NewLinkType);

/*!
  \brief Gets the link type of the specified adapter
  \param AdapterHandle Handle to the adapter.
  \param PLinkType Pointer to a caller allocated AirpcapLinkType variable that will contain the link type of the adapter.
  \return TRUE on success.
  the "link type" determines how the driver will encode the packets captured from the network.
  Aircap supports two link types:
  - \ref AIRPCAP_LT_802_11, to capture 802.11 frames (including control frames) without any
   power information. Look at the "Capture_no_radio" example application in the developer's pack 
   for a reference on how to decode 802.11 frames with this link type.
  - \ref AIRPCAP_LT_802_11_PLUS_RADIO, to capture 802.11 frames (including control frames) with a radiotap header
  that contains power and channel information. More information about the radiotap header can be found int the
  \ref radiotap section. Moreover, the "Capture_radio" example application in 
  the developer's pack can be used as a reference on how to decode 802.11 frames with radiotap headers.
  - \ref AIRPCAP_LT_802_11_PLUS_PPI, to capture 802.11 frames (including control frames) with a Per Packet Information (PPI)
	header that contains per-packet meta information like channel and power information. More details on the PPI header can
	be found in the PPI online documentation (TODO).
*/
BOOL AirpcapGetLinkType(PAirpcapHandle AdapterHandle, PAirpcapLinkType PLinkType);

/*!
  \brief Configures the adapter on whether to include the MAC Frame Check Sequence in the captured packets.
  \param AdapterHandle Handle to the adapter.
  \param IsFcsPresent TRUE if the packets should include the FCS. FALSE otherwise
  \return TRUE on success.
  In the default configuration, the adapter includes the FCS in the captured packets. The MAC Frame Check Sequence 
  is 4 bytes and is located at the end of the 802.11 packet, with \ref AIRPCAP_LT_802_11, \ref AIRPCAP_LT_802_11_PLUS_RADIO and
  \ref AIRPCAP_LT_802_11_PLUS_PPI link types.
  When the FCS inclusion is turned on, and if the link type is \ref AIRPCAP_LT_802_11_PLUS_RADIO, the radiotap header 
  that precedes each frame has two additional fields at the end: Padding and FCS. These two fields are not present 
  when FCS inclusion is off.
*/	
BOOL AirpcapSetFcsPresence(PAirpcapHandle AdapterHandle, BOOL IsFcsPresent);

/*!
  \brief Returns TRUE if the specified adapter includes the MAC Frame Check Sequence in the captured packets 
  \param AdapterHandle Handle to the adapter.
  \param PIsFcsPresent User-provided variable that will be set to true if the adapter is including the FCS.
  \return TRUE if the operation is successful. FALSE otherwise.
  In the default configuration, the adapter includes the FCS in the captured packets. The MAC Frame Check Sequence 
  is 4 bytes and is located at the end of the 802.11 packet, with \ref AIRPCAP_LT_802_11, \ref AIRPCAP_LT_802_11_PLUS_RADIO and
  \ref AIRPCAP_LT_802_11_PLUS_PPI link types.
  When the FCS inclusion is turned on, and if the link type is \ref AIRPCAP_LT_802_11_PLUS_RADIO, the radiotap header 
  that precedes each frame has two additional fields at the end: Padding and FCS. These two fields are not present 
  when FCS inclusion is off.
*/
BOOL AirpcapGetFcsPresence(PAirpcapHandle AdapterHandle, PBOOL PIsFcsPresent);

/*!
  \brief Configures the adapter to accept or drop frames with an incorrect Frame Check sequence (FCS).
  \param AdapterHandle Handle to the adapter.
  \param ValidationType The type of validation the driver will perform. See the documentation of \ref AirpcapValidationType for details.
  \return TRUE on success.
  \note By default, the driver is configured in \ref AIRPCAP_VT_ACCEPT_EVERYTHING mode.
*/
BOOL AirpcapSetFcsValidation(PAirpcapHandle AdapterHandle, AirpcapValidationType ValidationType);

/*!
  \brief Checks if the specified adapter is configured to capture frames with incorrect an incorrect Frame Check Sequence (FCS). 
  \param AdapterHandle Handle to the adapter.
  \param ValidationType Pointer to a user supplied variable that will contain the type of validation the driver will perform. See the documentation of \ref AirpcapValidationType for details.
  \return TRUE if the operation is succesful. FALSE otherwise.
  \note By default, the driver is configured in \ref AIRPCAP_VT_ACCEPT_EVERYTHING mode.
*/
BOOL AirpcapGetFcsValidation(PAirpcapHandle AdapterHandle, PAirpcapValidationType ValidationType);

/*!
  \brief Sets the list of decryption keys that AirPcap is going to use with the specified device.
  \param AdapterHandle Handle an open adapter instance.
  \param KeysCollection Pointer to a \ref PAirpcapKeysCollection structure that contains the keys to be set in the device.
  \return TRUE if the operation is successful. FALSE otherwise.
  AirPcap is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application.
  This function allows to set the <b>device-specific</b> set of keys. These keys will be used by the specified device only,
  and will not be used by other airpcap devices besides the specified one. 
  At this time, the only supported decryption method is WEP.
  The keys are applied to the packets in the same order they appear in the KeysCollection structure until the packet is 
  correctly decrypted, therefore putting frequently used keys at the beginning of the structure improves performance.
  \note When you change the set of keys from an open capture instance, the change will be
         immediately reflected on all the other capture instances on the same device.
*/
BOOL AirpcapSetDeviceKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*!
  \brief Returns the list of decryption keys that are currently associated with the specified device 
  \param AdapterHandle Handle to an open adapter instance.
  \param KeysCollection User-allocated PAirpcapKeysCollection structure that will be filled with the keys.
  \param PKeysCollectionSize 
							- \b IN: pointer to a user-allocated variable that contains the length of the KeysCollection structure, in bytes.
							- \b OUT: amount of data moved by AirPcap in the buffer pointed by KeysBuffer, in bytes.
  \return TRUE if the operation is successful. If an error occurs, the return value is FALSE and KeysCollectionSize is zero. 
  If the provided buffer is too small to contain the keys, the return value is FALSE and KeysCollectionSize contains the
  needed KeysCollection length, in bytes. If the device doesn't have any decryption key configured, the return value is TRUE, and 
  KeysCollectionSize will be zero.
  
  This function returns the <b>device-specific</b> set of keys. These keys are used by the specified device only,
  and not by other airpcap devices besides the specified one. 
  AirPcap is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application. 
  AirPcap supports, for every device, multiple keys at the same time.
  The configured decryption keys are device-specific, therefore AirpcapGetDeviceKeys() will return a different set of keys
  when called on different devices.
  At this time, the only supported decryption method is WEP.
*/
BOOL AirpcapGetDeviceKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);

/*!
  \brief Set the global list of decryption keys that AirPcap is going to use with all the devices.
  \param AdapterHandle Handle an open adapter instance.
  \param KeysCollection Pointer to a \ref PAirpcapKeysCollection structure that contains the keys to be set globally.
  \return TRUE if the operation is successful. FALSE otherwise.
  The AirPcap driver is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application.
  This function allows to set the <b>global</b> set of keys. These keys will be used by all the devices plugged in
  the machine. 
  At this time, the only supported decryption method is WEP.
  The keys are applied to the packets in the same order they appear in the KeysCollection structure until the packet is 
  correctly decrypted, therefore putting frequently used keys at the beginning of the structure improves performance.
  \note When you change the set of keys from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapSetDriverKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection);

/*!
  \brief Returns the global list of decryption keys that AirPcap is using with all the devices.
  \param AdapterHandle Handle to an open adapter instance.
  \param KeysCollection User-allocated PAirpcapKeysCollection structure that will be filled with the keys.
  \param PKeysCollectionSize 
							- \b IN: pointer to a user-allocated variable that contains the length of the KeysCollection structure, in bytes.
							- \b OUT: amount of data moved by AirPcap in the buffer pointed by KeysBuffer, in bytes.
  \return TRUE if the operation is successful. If an error occurs, the return value is FALSE and KeysCollectionSize is zero. 
  If the provided buffer is too small to contain the keys, the return value is FALSE and KeysCollectionSize contains the
  needed KeysCollection length, in bytes. If no global decryption keys are configured, the return value is TRUE, and 
  KeysCollectionSize will be zero.
  
  This function returns the <b>global</b> set of keys. These keys will be used by all the devices plugged in
  the machine. 
  The AirPcap driver is able to use a set of decryption keys to decrypt the traffic transmitted on a specific SSID. If one of the
  keys corresponds to the one the frame has been encrypted with, the driver will perform decryption and return the cleartext frames
  to the application.
  At this time, the only supported decryption method is WEP.
*/
BOOL AirpcapGetDriverKeys(PAirpcapHandle AdapterHandle, PAirpcapKeysCollection KeysCollection, PUINT PKeysCollectionSize);

/*!
  \brief Turns on or off the decryption of the incoming frames with the <b>device-specific</b> keys.
  \param AdapterHandle Handle to the adapter.
  \param Enable Either \ref AIRPCAP_DECRYPTION_ON or \ref AIRPCAP_DECRYPTION_OFF
  \return TRUE on success.
  The device-specific decryption keys can be configured with the \ref AirpcapSetDeviceKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapSetDecryptionState(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);

/*!
  \brief Tells if this open instance is configured to perform the decryption of the incoming frames with the <b>device-specific</b> keys.
  \param AdapterHandle Handle to the adapter.
  \param PEnable Pointer to a user supplied variable that will contain the decryption configuration. See \ref PAirpcapDecryptionState for details.
  \return TRUE if the operation is succesful. FALSE otherwise.
  The device-specific decryption keys can be configured with the \ref AirpcapSetDeviceKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapGetDecryptionState(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);

/*!
  \brief Turns on or off the decryption of the incoming frames with the <b>global</b> set of keys.
  \param AdapterHandle Handle to the adapter.
  \param Enable Either \ref AIRPCAP_DECRYPTION_ON or \ref AIRPCAP_DECRYPTION_OFF
  \return TRUE on success.
  The global decryption keys can be configured with the \ref AirpcapSetDriverKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapSetDriverDecryptionState(PAirpcapHandle AdapterHandle, AirpcapDecryptionState Enable);

/*!
  \brief Tells if this open instance is configured to perform the decryption of the incoming frames with the <b>global</b> set of keys.
  \param AdapterHandle Handle to the adapter.
  \param PEnable Pointer to a user supplied variable that will contain the decryption configuration. See \ref PAirpcapDecryptionState for details.
  \return TRUE if the operation is successful. FALSE otherwise.
  The global decryption keys can be configured with the \ref AirpcapSetDriverKeys() function.
  \note By default, the driver is configured with \ref AIRPCAP_DECRYPTION_ON.
*/
BOOL AirpcapGetDriverDecryptionState(PAirpcapHandle AdapterHandle, PAirpcapDecryptionState PEnable);

/*!
  \brief Sets the radio channel of a device
  \param AdapterHandle Handle to the adapter.
  \param Channel the new channel to set.
  \return TRUE on success.
  The list of available channels can be retrieved with \ref AirpcapGetDeviceSupportedChannels(). The default channel setting is 6.
  \note This is a device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapSetDeviceChannel(PAirpcapHandle AdapterHandle, UINT Channel);

/*!
  \brief Gets the radio channel of a device
  \param AdapterHandle Handle to the adapter.
  \param PChannel Pointer to a user-supplied variable into which the function will copy the currently configured radio channel.
  \return TRUE on success.
  The list of available channels can be retrieved with \ref AirpcapGetDeviceSupportedChannels(). The default channel setting is 6.
  \note This is a device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapGetDeviceChannel(PAirpcapHandle AdapterHandle, PUINT PChannel);

/*!
  \brief Sets the channel of a device through its radio frequency. In case of 802.11n enabled devices, it sets the extension channel, if used.
  \param AdapterHandle Handle to the adapter.
  \param ChannelInfo The new channel information to set.
  \return TRUE on success.
  \note This is a device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapSetDeviceChannelEx(PAirpcapHandle AdapterHandle, AirpcapChannelInfo ChannelInfo);

/*!
  \brief Gets the channel of a device through its radio frequency. In case of 802.11n enabled devices, it gets the extension channel, if in use.
  \param AdapterHandle Handle to the adapter.
  \param PChannelInfo Pointer to a user-supplied variable into which the function will copy the currently configured channel information.
  \return TRUE on success.
  \note This is a device-related function: when you change the channel from an open capture instance, the change will be
         immediately reflected on all the other capture instances.
*/
BOOL AirpcapGetDeviceChannelEx(PAirpcapHandle AdapterHandle, PAirpcapChannelInfo PChannelInfo);

/*!
  \brief Gets the list of supported channels for a given device. In case of a 802.11n capable device, information related to supported extension channels is also reported. 
  Every control channel is listed multiple times, one for each different supported extension channel. For example channel 6 (2437MHz)  is usually listed three times:
	- <b>Frequency 2437 Extension +1</b>. Control channel is 6, extension channel is 10.
	- <b>Frequency 2437 Extension 0</b>. Control channel is 6, no extension channel is used (20MHz channel and legacy mode).
	- <b>Frequency 2437 Extension -1</b>. Control channel is 6, extension channel is 2.
  \param AdapterHandle Handle to the adapter.
  \param ppChannelInfo Pointer to a user-supplied variable that will point to an array of supported channel. Such list must not be freed by the caller
  \param pNumChannelInfo Number of channels returned in the array.
  \return TRUE on success.
  \note The supported channels are not listed in any specific order.
*/
BOOL AirpcapGetDeviceSupportedChannels(PAirpcapHandle AdapterHandle, PAirpcapChannelInfo *ppChannelInfo, PUINT pNumChannelInfo);

/*!
  \brief Converts a given frequency to the corresponding channel.
  \param Frequency Frequency of the channel, in MHz.
  \param PChannel Pointer to a user-supplied variable that will contain the channel number on success.
  \param PBand Pointer to a user-supplied variable that will contain the band (a or b/g) of the given channel.
  \return TRUE on success, i.e. the frequency corresponds to a valid a or b/g channel.
*/
BOOL AirpcapConvertFrequencyToChannel(UINT Frequency, PUINT PChannel, PAirpcapChannelBand PBand);

/*!
  \brief Converts a given channel to the corresponding frequency.
  \param Channel Channel number to be converted.
  \param PFrequency Pointer to a user-supplied variable that will contain the channel frequency in MHz on success.
  \return TRUE on success, i.e. the given channel number exists.
  Because of the overlap of channels with respect to 1-14BG and 1-14A, this function will give precidence to BG.
  Thus, the channels are returned as follows:
    - <b>Channel 0:</b> 5000MHz
    - <b>Channels 1-14:</b> 2412MHz - 2484MHz
	- <b>Channels 15-239:</b> 5005MHz - 6195MHz
	- <b>Channels 240-255:</b> 4920MHz - 4995MHz
*/
BOOL AirpcapConvertChannelToFrequency(UINT Channel, PUINT PFrequency);

/*!
  \brief Sets the size of the kernel packet buffer for this adapter
  \param AdapterHandle Handle to the adapter.
  \param BufferSize New size, in bytes.
  \return TRUE on success.
  Every AirPcap open instance has an associated kernel buffer, whose default size is 1 Mbyte.
  This function can be used to change the size of this buffer, and can be called at any time.
  A bigger kernel buffer size decreases the risk of dropping packets during network bursts or when the
  application is busy, at the cost of higher kernel memory usage.
  \note Don't use this function unless you know what you are doing. Due to caching issues and bigger non-paged
  memory consumption, bigger buffer sizes can decrease the capture performace instead of improving it.
*/
BOOL AirpcapSetKernelBuffer(PAirpcapHandle AdapterHandle, UINT BufferSize);

/*!
  \brief Gets the size of the kernel packet buffer for this adapter
  \param AdapterHandle Handle to the adapter.
  \param PSizeBytes User-allocated variable that will be filled with the size of the kernel buffer.
  \return TRUE on success.
  Every AirPcap open instance has an associated kernel buffer, whose default size is 1 Mbyte.
  This function can be used to get the size of this buffer.
*/
BOOL AirpcapGetKernelBufferSize(PAirpcapHandle AdapterHandle, PUINT PSizeBytes);

/*!
  \brief Sets the power of the frames are transmitted by adapter.
  \param AdapterHandle Handle to the adapter.
  \param Power The transmit power. Setting a zero power makes the adapter select the highest possible power for the
         current channel.
  \return TRUE on success. False on failure or if the adapter doesn't support setting the transmit power.
  The transmit power value is monotonically increasing with higher power levels. 1 is the minimum allowed transmit power.
  \note The maximum transmit power on each channel is limited by FCC regulations. Therefore, the maximum transmit power
  changes from channel to channel. When the channel is changed with \ref AirpcapSetDeviceChannel() or 
  \ref AirpcapSetDeviceChannelEx() the power is set to the maximum allowd value for that channel. You can read this
  value with \ref AirpcapGetTxPower(). Not all the AirPcap adapters support setting the transmit power; you can use
  \ref AirpcapGetDeviceCapabilities() to find if the current adapter supports this feature.
*/
BOOL AirpcapSetTxPower(PAirpcapHandle AdapterHandle, UINT Power);

/*!
  \brief Returns the current transmit power level of the adapter.
  \param AdapterHandle Handle to the adapter.
  \param PPower User-allocated variable that will be filled with the size of the transmit power.
  \return TRUE on success. False on failure or if the adapter doesn't support getting the transmit power.
  The transmit power value is monotonically increasing with higher power levels. 0 is the minimum allowed power.
  \note The maximum transmit power on each channel is limited by FCC regulations. Therefore, the maximum transmit power
  changes from channel to channel. When the channel is changed with \ref AirpcapSetDeviceChannel() or 
  \ref AirpcapSetDeviceChannelEx() the power is set to the maximum allowd value for that channel. Not all the AirPcap 
  adapters support setting the transmit power; you can use \ref AirpcapGetDeviceCapabilities() to find if the current 
  adapter supports this feature.
*/
BOOL AirpcapGetTxPower(PAirpcapHandle AdapterHandle, PUINT PPower);

/*!
  \brief Saves the configuration of the specified adapter in the registry, so that it becomes the default for this adapter.
  \param AdapterHandle Handle to the adapter.
  \return TRUE on success. FALSE on failure.
  Almost all the AirPcap calls that modify the configuration (\ref AirpcapSetLinkType(), \ref AirpcapSetFcsPresence(), 
  \ref AirpcapSetFcsValidation(), \ref AirpcapSetKernelBuffer(), \ref AirpcapSetMinToCopy())
  affect only the referenced AirPcap open instance. This means that if you do another \ref AirpcapOpen() on the same
  adapter, the configuration changes will not be remembered, and the new adapter handle will have default configuration
  settings.
  Exceptions to this rule are the \ref AirpcapSetDeviceChannel() and \ref AirpcapSetDeviceKeys() functions: a channel change is 
  reflected on all the open instances, and remembered until the next call to \ref AirpcapSetDeviceChannel(), until the adapter 
  is unplugged, or until the machine is powered off. Same thing for the configuration of the WEP keys.
  AirpcapStoreCurConfigAsAdapterDefault() stores the configuration of the give open instance as the default for the adapter: 
  all the instances opened in the future will have the same configuration that this adapter currently has.
  The configuration is stored in the registry, therefore it is remembered even when the adapter is unplugged or the
  machine is turned off. However, an adapter doesn't bring its configuration with it from machine to machine.
  the configuration information saved in the registry includes the following parameters:
   - channel
   - kernel buffer size
   - mintocopy
   - link type
   - CRC presence
   - Encryption keys
   - Encryption Enabled/Disabled state
  The configuration is device-specific. This means that changing the configuration of a device
  doesn't modify the one of the other devices that are currently used or that will be used in the future.
  \note AirpcapStoreCurConfigAsAdapterDefault() must have exclusive access to the adapter -- it 
   will fail if more than one AirPcap handle is opened at the same time for this device. 
   AirpcapStoreCurConfigAsAdapterDefault() needs administrator privileges. It will fail if the calling user
   is not a local machine administrator.
*/
BOOL AirpcapStoreCurConfigAsAdapterDefault(PAirpcapHandle AdapterHandle);

/*!
  \brief Sets the BPF kernel filter for an adapter
  \param AdapterHandle Handle to the adapter.
  \param Instructions pointer to the first BPF instruction in the array. Corresponds to the  bf_insns 
   in a bpf_program structure (see the WinPcap documentation at http://www.winpcap.org/devel.htm).
  \param Len Number of instructions in the array pointed by the previous field. Corresponds to the bf_len in
  a a bpf_program structure (see the WinPcap documentation at http://www.winpcap.org/devel.htm).
  \return TRUE on success.
  The AirPcap driver is able to perform kernel-level filtering using the standard BPF pseudo-machine format. You can read
  the WinPcap documentation at http://www.winpcap.org/devel.htm for more details on the BPF filtering mechaism.
  A filter can be automatically created by using the pcap_compile() function of the WinPcap API. This function 
  converts a human readable text expression with the tcpdump/libpcap syntax into a BPF program. 
  If your program doesn't link wpcap, but you need to generate the code for a particular filter, you can run WinDump 
  with the -d or -dd or -ddd flags to obtain the pseudocode.
*/
BOOL AirpcapSetFilter(PAirpcapHandle AdapterHandle, PVOID Instructions, UINT Len);

/*!
  \brief Returns the MAC address of a device.
  \param AdapterHandle Handle to the adapter.
  \param PMacAddress Pointer to a user allocated \ref AirpcapMacAddress structure that will receive the MAC address on success. 
  \return TRUE on success.
*/
BOOL AirpcapGetMacAddress(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);

/*!
  \brief Sets the MAC address of a device.
  \param AdapterHandle Handle to the adapter.
  \param PMacAddress Pointer to a user-initialized structure containing the MAC address.
  \return TRUE on success. FALSE on failure, or if the adapter doesn't support changing the address.
  Using this function, the programmer can change the MAC address of the device. This is useful when disabling monitor
  mode with \ref AirpcapSetDeviceMacFlags(), because the device will acknowledge the data frames sent to its MAC address.
  
  \note The address change is temporary: when the device is unplugged or when the host PC is turned off, the address is reset to the original
  value.
*/
BOOL AirpcapSetMacAddress(PAirpcapHandle AdapterHandle, PAirpcapMacAddress PMacAddress);

/*!
  \brief Sets the mintocopy parameter for an open adapter.
  \param AdapterHandle Handle to the adapter.
  \param MinToCopy is the mintocopy size in bytes.
  \return TRUE on success.
  When the number of bytes in the kernel buffer changes from less than mintocopy bytes to greater than or equal to mintocopy bytes, 
  the read event is signalled (see \ref AirpcapGetReadEvent()). A high value for mintocopy results in poor responsiveness since the
  driver may signal the application "long" after the arrival of the packet. And a high value results in low CPU loading
  by minimizing the number of user/kernel context switches. 
  A low MinToCopy results in good responsiveness since the driver will signal the application close to the arrival time of
  the packet. This has higher CPU loading over the first approach.
*/
BOOL AirpcapSetMinToCopy(PAirpcapHandle AdapterHandle, UINT MinToCopy);

/*!
  \brief Gets an event that is signalled when packets are available in the kernel buffer (see \ref AirpcapSetMinToCopy()).
  \param AdapterHandle Handle to the adapter.
  \param PReadEvent Pointer to a user-supplied handle in which the read event will be copied.
  \return TRUE on success.
  \note The event is signalled when at least mintocopy bytes are present in the kernel buffer (see \ref AirpcapSetMinToCopy()). 
  This event can be used by WaitForSingleObject() and WaitForMultipleObjects() to create blocking behavior when reading 
  packets from one or more adapters (see \ref AirpcapRead()).
*/
BOOL AirpcapGetReadEvent(PAirpcapHandle AdapterHandle, HANDLE* PReadEvent);

/*!
  \brief Fills a user-provided buffer with zero or more packets that have been captured on the referenced adapter.
  \param AdapterHandle Handle to the adapter.
  \param Buffer pointer to the buffer that will be filled with captured packets.
  \param BufSize size of the input buffer that will contain the packets, in bytes.
  \param PReceievedBytes Pointer to a user supplied variable that will receive the number of bytes copied by AirpcapRead. 
  Can be smaller than BufSize.
  \return TRUE on success.
  802.11 frames are returned by the driver in buffers. Every 802.11 frame in the buffer is preceded by a \ref AirpcapBpfHeader structure.
  The suggested way to use an AirPcap adapter is through the pcap API exported by wpcap.dll. If this is not
  possible, the Capture_radio and Capture_no_radio examples in the AirPcap developer's pack show how to properly decode the 
  packets in the read buffer returned by AirpcapRead().
  \note This function is NOT blocking. Blocking behavior can be obtained using the event returned
   by \ref AirpcapGetReadEvent(). See also \ref AirpcapSetMinToCopy().
*/
BOOL AirpcapRead(PAirpcapHandle AdapterHandle, PBYTE Buffer, UINT BufSize, PUINT PReceievedBytes);

/*!
  \brief Transmits a packet.
  \param AdapterHandle Handle to the adapter.
  \param TxPacket Pointer to a buffer that contains the packet to be transmitted.
  \param PacketLen Length of the buffer pointed by the TxPacket argument, in bytes.
  \return TRUE on success.
  The packet will be transmitted on the channel the device is currently set. To change the device adapter, use the 
  \ref AirpcapSetDeviceChannel() function.
  If the link type of the adapter is AIRPCAP_LT_802_11, the buffer pointed by TxPacket should contain just the 802.11
  packet, without additional information. The packet will be transmitted at 1Mbps.
  If the link type of the adapter is AIRPCAP_LT_802_11_PLUS_RADIO, the buffer pointed by TxPacket should contain a radiotap
  header followed by the 802.11 packet. AirpcapWrite will use the rate information in the radiotap header when
  transmitting the packet.
  
  If the link type of the adapter is AIRPCAP_LT_802_11_PLUS_PPI, the buffer pointed by TxPacket should contain a PPI header 
  followed by the 802.11 packet. AirpcapWrite will use the rate information in the PPI header when transmitting the packet.
  If the packet should be transmitted at a 802.11n rate, the packet must include a PPI 802.11n MAC+PHY Extension header, containing
  the rate expressed in terms of MCS, short/long guard interval (SGI/LGI) and 20MHz or 40MHz channel. When the MAC+PHY Extension header is present,
  the rate field in the PPI 802.11-Common header is ignored.
  By default on 802.11n-capable AirPcap adapters, packets are transmitted with no A-MPDU aggregation. A-MPDU aggregation is controlled by the
  adapter, but it's possible to give a hint to the hardware to aggregate some packets by setting the "Aggregate" and "More aggregates" flags in 
  the PPI 802.11n MAC+PHY extension header.
  
*/
BOOL AirpcapWrite(PAirpcapHandle AdapterHandle, PCHAR TxPacket, ULONG PacketLen);

/*!
  \brief Gets per-adapter WinPcap-compatible capture statistics.
  \param AdapterHandle Handle to the adapter.
  \param PStats pointer to a user-allocated AirpcapStats structure that will be filled with statistical information.
  \return TRUE on success.
*/
BOOL AirpcapGetStats(PAirpcapHandle AdapterHandle, PAirpcapStats PStats);

/*!
  \brief Gets the number of LEDs the referenced adapter has available.
  \param AdapterHandle Handle to the adapter.
  \param NumberOfLeds Number of LEDs available on this adapter.
  \return TRUE on success.
*/
BOOL AirpcapGetLedsNumber(PAirpcapHandle AdapterHandle, PUINT NumberOfLeds);

/*!
  \brief Turns on one of the adapter's LEDs.
  \param AdapterHandle Handle to the adapter.
  \param LedNumber zero-based identifier of the LED to turn on.
  \return TRUE on success.
*/
BOOL AirpcapTurnLedOn(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*!
  \brief Turns off one of the adapter's LEDs.
  \param AdapterHandle Handle to the adapter.
  \param LedNumber zero-based identifier of the LED to turn off.
  \return TRUE on success.
*/
BOOL AirpcapTurnLedOff(PAirpcapHandle AdapterHandle, UINT LedNumber);

/*!
  \brief Gets the current value of the device counter used to timestamp packets.
  \param AdapterHandle Handle to the adapter.
  \param PTimestamp Pointer to a caller allocated 64bit integer that will receive the device
		timestamp, in microseconds.
  \return TRUE on success.
*/
BOOL AirpcapGetDeviceTimestamp(PAirpcapHandle AdapterHandle, PAirpcapDeviceTimestamp PTimestamp);

/*@}*/

#endif // __AIRPCAP_DRIVER__

#ifdef __cplusplus
}
#endif

#endif // !defined(AIRPCAP_H__EAE405F5_0171_9592_B3C2_C19EC426AD34__INCLUDED_)
