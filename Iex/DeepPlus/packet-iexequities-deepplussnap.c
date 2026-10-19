/* packet-iexequities-deepplussnap.c
 * Routines for IEX DEEP+ SNAP dissection
 *
 * Aggregated protocol versions: 1.06
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Iex.IexEquities.DeepPlus.Snap.v1.06
 *
 * Authors: Omi Developers
 *
 * The Open Markets Initiative
 *   https://openmarketsinitiative.com
 *
 * Copyright (c) 2026 Scaled Sources LLC.
 *   https://www.scaledsources.com
 *
 * This dissector code is contributed by The Open Markets Initiative under
 * the license noted below.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

void proto_register_iexequities_deepplussnap(void);
void proto_reg_handoff_iexequities_deepplussnap(void);

static dissector_handle_t iexequities_deepplussnap_handle;

static int proto_iexequities_deepplussnap;

/*
 * IexEquities DeepPlus Protocol
 */

#define IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_NAME "IEX DEEP+ SNAP"
#define IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_SHORT "IEXEQUITIES.DEEPPLUSSNAP"
#define IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_FILTER "iexequities.deepplussnap"

/*
 * IexEquities DeepPlus Header
 */

#define IEXEQUITIES_DEEPPLUSSNAP_HEADER_SIZE 3 /* Message */

/*
 * IexEquities DeepPlus Field Handles
 */

static int hf_iexequities_deepplussnap_adjusted_poc_price;
static int hf_iexequities_deepplussnap_authentication_token;
static int hf_iexequities_deepplussnap_channel_id;
static int hf_iexequities_deepplussnap_detail;
static int hf_iexequities_deepplussnap_etp;
static int hf_iexequities_deepplussnap_extended_hours;
static int hf_iexequities_deepplussnap_first_message_sequence_number;
static int hf_iexequities_deepplussnap_iex_tp_message_block_length;
static int hf_iexequities_deepplussnap_iex_tp_message_length;
static int hf_iexequities_deepplussnap_iex_tp_message_type;
static int hf_iexequities_deepplussnap_intermarket_sweep;
static int hf_iexequities_deepplussnap_luld_tier;
static int hf_iexequities_deepplussnap_message_count;
static int hf_iexequities_deepplussnap_message_length;
static int hf_iexequities_deepplussnap_message_protocol_id;
static int hf_iexequities_deepplussnap_message_type;
static int hf_iexequities_deepplussnap_minimum_sequence_number;
static int hf_iexequities_deepplussnap_modify_flags;
static int hf_iexequities_deepplussnap_odd_lot;
static int hf_iexequities_deepplussnap_operational_halt_status;
static int hf_iexequities_deepplussnap_order_id;
static int hf_iexequities_deepplussnap_order_id_reference;
static int hf_iexequities_deepplussnap_payload_length;
static int hf_iexequities_deepplussnap_price;
static int hf_iexequities_deepplussnap_priority;
static int hf_iexequities_deepplussnap_reason;
static int hf_iexequities_deepplussnap_reject_reason_code;
static int hf_iexequities_deepplussnap_reserved;
static int hf_iexequities_deepplussnap_reserved_1;
static int hf_iexequities_deepplussnap_retail_liquidity_indicator;
static int hf_iexequities_deepplussnap_round_lot_size;
static int hf_iexequities_deepplussnap_sale_condition_flags;
static int hf_iexequities_deepplussnap_security_directory_flags;
static int hf_iexequities_deepplussnap_security_event;
static int hf_iexequities_deepplussnap_send_time;
static int hf_iexequities_deepplussnap_session_id;
static int hf_iexequities_deepplussnap_short_sale_price_test_status;
static int hf_iexequities_deepplussnap_side;
static int hf_iexequities_deepplussnap_singleprice_cross_trade;
static int hf_iexequities_deepplussnap_size;
static int hf_iexequities_deepplussnap_snapshot_length;
static int hf_iexequities_deepplussnap_snapshot_sequence_number;
static int hf_iexequities_deepplussnap_stream_offset;
static int hf_iexequities_deepplussnap_symbol;
static int hf_iexequities_deepplussnap_system_event;
static int hf_iexequities_deepplussnap_test_security;
static int hf_iexequities_deepplussnap_timestamp;
static int hf_iexequities_deepplussnap_trade_id;
static int hf_iexequities_deepplussnap_trade_through_exempt;
static int hf_iexequities_deepplussnap_trading_status;
static int hf_iexequities_deepplussnap_version;
static int hf_iexequities_deepplussnap_when_issued;

/*
 * IexEquities DeepPlus Subtrees
 */

static int ett_iexequities_deepplussnap;
static int ett_iexequities_deepplussnap_header;
static int ett_iexequities_deepplussnap_message;
static int ett_iexequities_deepplussnap_security_directory_flags;
static int ett_iexequities_deepplussnap_modify_flags;
static int ett_iexequities_deepplussnap_sale_condition_flags;
static int ett_iexequities_deepplussnap_message_header;
static int ett_iexequities_deepplussnap_iextp_header;

/*
 * IexEquities DeepPlus Expert Information
 */

/* Message length does not account for the parsed fields */
#define IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_FILTER "iexequities.deepplussnap.length.invalid"
#define IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_GROUP PI_MALFORMED
#define IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_SEVERITY PI_ERROR
#define IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_iexequities_deepplussnap_length;

/*
 * IexEquities DeepPlus Preferences
 */

#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_NAME "version"
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_TITLE "Protocol version"
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_AUTOMATIC 0
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_1_06     1

static const enum_val_t iexequities_deepplussnap_version_vals[] = {
    { "automatic", "Automatic (by send time)", IEXEQUITIES_DEEPPLUSSNAP_VERSION_AUTOMATIC },
    { "v1.06", "1.06", IEXEQUITIES_DEEPPLUSSNAP_VERSION_1_06 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
iexequities_deepplussnap_version_name(int version)
{
    switch (version) {
    case IEXEQUITIES_DEEPPLUSSNAP_VERSION_1_06:
        return "1.06";
    }

    return "";
}

static int iexequities_deepplussnap_pref_version = IEXEQUITIES_DEEPPLUSSNAP_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */

/* Show preferences, one per message and struct */
#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

static bool iexequities_deepplussnap_show_headers = true;
static bool iexequities_deepplussnap_show_application_messages = true;

/* Decimal places shown, the wire precision by default */
#define IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_NAME "decimal.places"
#define IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned iexequities_deepplussnap_pref_decimal_places = 4;

/* Ports the feed arrives on, assigned per deployment */
#define IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_NAME "ports"
#define IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_TITLE "Ports"
#define IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_DEFAULT "11379,33381"
#define IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *iexequities_deepplussnap_pref_ports;

/*
 * IexEquities DeepPlus Methods
 */

/* Select the protocol version, this protocol has one */
static int
iexequities_deepplussnap_version(uint64_t seconds _U_)
{
    return IEXEQUITIES_DEEPPLUSSNAP_VERSION_1_06;
}

/* Cap the fraction at the preferred decimal places */
static void
iexequities_deepplussnap_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = iexequities_deepplussnap_pref_decimal_places;

    if (places >= strlen(point + 1)) {
        return;
    }

    if (places == 0) {
        *point = '\0';
        return;
    }

    point[1 + places] = '\0';
}

/* Format an implied 4 decimal place value */
static void
iexequities_deepplussnap_format_decimal_4_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t units = value / 10000;
    int64_t fraction = value % 10000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%04" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%04" PRId64, units, fraction);
    }

    iexequities_deepplussnap_decimal_places(buf);
}

/*
 * IexEquities DeepPlus Fields
 */

/* Adjusted Poc Price */
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_NAME        "Adjusted Poc Price"
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_DESCRIPTION "Corporate action adjusted previous official closing price"
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_FILTER      "iexequities.deepplussnap.adjustedpocprice"
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_SIZE        8

static unsigned
parse_iexequities_deepplussnap_adjusted_poc_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_adjusted_poc_price, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_SIZE;
}

/* Authentication Token */
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_NAME        "Authentication Token"
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_DESCRIPTION "Token supplied by Iex Market Ops, left justified and space padded on the right"
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_FILTER      "iexequities.deepplussnap.authenticationtoken"
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_TYPE        FT_STRING
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_DISPLAY     BASE_NONE
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_SIZE        40

static unsigned
parse_iexequities_deepplussnap_authentication_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_authentication_token, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_SIZE, IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_SIZE;
}

/* Channel Id */
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_NAME        "Channel Id"
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_DESCRIPTION "Channel identifier from the Deep Plus feed IexTp header"
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_FILTER      "iexequities.deepplussnap.channelid"
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_TYPE        FT_UINT32
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_SIZE        4

static unsigned
parse_iexequities_deepplussnap_channel_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_channel_id, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_SIZE, IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_SIZE;
}

/* Detail */
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_NAME        "Detail"
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_DESCRIPTION "Detail of the Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_FILTER      "iexequities.deepplussnap.detail"
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_DETAIL_SIZE        1

static const value_string iexequities_deepplussnap_detail_vals[] = {
    { ' ', "No Price Test In Place" },
    { 'A', "Short Sale Price Test Restriction In Effect Due To An Intraday Price Drop In The Security" },
    { 'C', "Short Sale Price Test Restriction Remains In Effect From Prior Day" },
    { 'D', "Short Sale Price Test Restriction Deactivated" },
    { 'N', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_detail(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_detail, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_DETAIL_SIZE, IEXEQUITIES_DEEPPLUSSNAP_DETAIL_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_DETAIL_SIZE;
}

/* Etp */
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_NAME        "Etp"
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_DESCRIPTION "Symbol is an ETP"
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_FILTER      "iexequities.deepplussnap.etp"
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_ETP_MASK        0x20

/* Extended Hours */
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_NAME        "Extended Hours"
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_DESCRIPTION "Extended Hours Trade"
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_FILTER      "iexequities.deepplussnap.extendedhours"
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_MASK        0x40

/* First Message Sequence Number */
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME        "First Message Sequence Number"
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION "Sequence of the first message in the segment"
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER      "iexequities.deepplussnap.firstmessagesequencenumber"
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_deepplussnap_first_message_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_first_message_sequence_number, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE;
}

/* Iex Tp Message Block Length */
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_NAME        "Iex Tp Message Block Length"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DESCRIPTION "Length in bytes of the IexTp message block that follows this field: the IexTp Message Length field and the message"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_FILTER      "iexequities.deepplussnap.iextpmessageblocklength"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE        2

static unsigned
parse_iexequities_deepplussnap_iex_tp_message_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_iex_tp_message_block_length, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE;
}

/* Iex Tp Message Length */
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_NAME        "Iex Tp Message Length"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_DESCRIPTION "Length of the wrapped Deep Plus message in bytes not including this field"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_FILTER      "iexequities.deepplussnap.iextpmessagelength"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_iexequities_deepplussnap_iex_tp_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_iex_tp_message_length, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE;
}

/* Iex Tp Message Type values the dispatch switches on */
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT                 'S'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY           'D'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS               'H'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR   'I'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS      'O'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS 'P'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_EVENT               'E'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ADD_ORDER                    'a'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_MODIFY                 'M'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_DELETE                 'R'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_EXECUTED               'L'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE                        'T'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK                  'B'
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_CLEAR_BOOK                   'C'

/* Iex Tp Message Type */
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_NAME        "Iex Tp Message Type"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_DESCRIPTION "Code identifying the wrapped Deep Plus message type"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_FILTER      "iexequities.deepplussnap.iextpmessagetype"
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SIZE        1

static const value_string iexequities_deepplussnap_iex_tp_message_type_vals[] = {
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_EVENT, "Security Event Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ADD_ORDER, "Add Order Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_MODIFY, "Order Modify Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE, "Trade Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_CLEAR_BOOK, "Clear Book Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_iex_tp_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_iex_tp_message_type, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SIZE;
}

/* Intermarket Sweep */
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_NAME        "Intermarket Sweep"
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_DESCRIPTION "Intermarket Sweep Order"
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_FILTER      "iexequities.deepplussnap.intermarketsweep"
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_MASK        0x80

/* Luld Tier */
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_NAME        "Luld Tier"
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_DESCRIPTION "Indicates which Limit Up-Limit Down price band calculation parameter is to be used"
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_FILTER      "iexequities.deepplussnap.luldtier"
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_TYPE        FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_SIZE        1

static const value_string iexequities_deepplussnap_luld_tier_vals[] = {
    { 0, "Not Applicable" },
    { 1, "Tier 1 Nms Stock" },
    { 2, "Tier 2 Nms Stock" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_luld_tier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_luld_tier, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_SIZE, IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_SIZE;
}

/* Message Count */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_NAME        "Message Count"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_DESCRIPTION "Number of messages in the payload"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_FILTER      "iexequities.deepplussnap.messagecount"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_SIZE        2

static unsigned
parse_iexequities_deepplussnap_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_message_count, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_SIZE, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_SIZE;
}

/* Message Length */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_NAME        "Message Length"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_DESCRIPTION "Length of message in bytes not including this field"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_FILTER      "iexequities.deepplussnap.messagelength"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_iexequities_deepplussnap_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_message_length, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_SIZE, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_SIZE;
}

/* Message Protocol Id */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_NAME        "Message Protocol Id"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_DESCRIPTION "Unique identifier of the higher layer protocol"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_FILTER      "iexequities.deepplussnap.messageprotocolid"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_SIZE        2

static unsigned
parse_iexequities_deepplussnap_message_protocol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_message_protocol_id, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_SIZE, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_SIZE;
}

/* Message Type values the dispatch switches on */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST 'r'
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ERROR_RESPONSE   'e'
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_START   's'
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA    'd'
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_END     'x'

/* Message Type */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_NAME        "Message Type"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_DESCRIPTION "Code identifying this message type"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_FILTER      "iexequities.deepplussnap.messagetype"
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SIZE        1

static const value_string iexequities_deepplussnap_message_type_vals[] = {
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST, "Snapshot Request Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ERROR_RESPONSE, "Error Response Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_START, "Snapshot Start Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA, "Snapshot Data Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_END, "Snapshot End Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_message_type, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SIZE;
}

/* Minimum Sequence Number */
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_NAME        "Minimum Sequence Number"
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_DESCRIPTION "Minimum sequence number useable by the client, zero returns the latest snapshot available"
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_FILTER      "iexequities.deepplussnap.minimumsequencenumber"
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_deepplussnap_minimum_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_minimum_sequence_number, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE;
}

/* Odd Lot */
#define IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_NAME    "Odd Lot"
#define IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_FILTER  "iexequities.deepplussnap.oddlot"
#define IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_TYPE    FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_DISPLAY 8
#define IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_MASK    0x20

/* Operational Halt Status */
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_NAME        "Operational Halt Status"
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_DESCRIPTION "Operational halt status identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_FILTER      "iexequities.deepplussnap.operationalhaltstatus"
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_SIZE        1

static const value_string iexequities_deepplussnap_operational_halt_status_vals[] = {
    { 'O', "Iex Specific Operational Trading Halt" },
    { 'N', "Not Operationally Halted On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_operational_halt_status, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_SIZE, IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_SIZE;
}

/* Order Id */
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_NAME        "Order Id"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_DESCRIPTION "Order ID of new order"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_FILTER      "iexequities.deepplussnap.orderid"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_SIZE        8

static unsigned
parse_iexequities_deepplussnap_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_order_id, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_SIZE, IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_SIZE;
}

/* Order Id Reference */
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_NAME        "Order Id Reference"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_DESCRIPTION "Order ID of the referenced order"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_FILTER      "iexequities.deepplussnap.orderidreference"
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_SIZE        8

static unsigned
parse_iexequities_deepplussnap_order_id_reference(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_order_id_reference, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_SIZE;
}

/* Payload Length */
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_NAME        "Payload Length"
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_DESCRIPTION "Byte length of the payload"
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_FILTER      "iexequities.deepplussnap.payloadlength"
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_SIZE        2

static unsigned
parse_iexequities_deepplussnap_payload_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_payload_length, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_SIZE, IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_SIZE;
}

/* Price */
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_NAME        "Price"
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_DESCRIPTION "Booking price on the IEX Order Book"
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_FILTER      "iexequities.deepplussnap.price"
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_PRICE_SIZE        8

static unsigned
parse_iexequities_deepplussnap_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_price, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_PRICE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_PRICE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_PRICE_SIZE;
}

/* Priority */
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_NAME        "Priority"
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_DESCRIPTION "Order Priority"
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_FILTER      "iexequities.deepplussnap.priority"
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_MASK        0x80

/* Reason */
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_NAME        "Reason"
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_DESCRIPTION "Reason for the trading status change"
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_FILTER      "iexequities.deepplussnap.reason"
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_TYPE        FT_STRING
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_DISPLAY     BASE_NONE
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_REASON_SIZE        4

static unsigned
parse_iexequities_deepplussnap_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_reason, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_REASON_SIZE, IEXEQUITIES_DEEPPLUSSNAP_REASON_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_REASON_SIZE;
}

/* Reject Reason Code */
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_NAME        "Reject Reason Code"
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_DESCRIPTION "Reason the Snapshot Request was rejected"
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_FILTER      "iexequities.deepplussnap.rejectreasoncode"
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_SIZE        1

static const value_string iexequities_deepplussnap_reject_reason_code_vals[] = {
    { 'A', "Authentication Failure" },
    { 'C', "Incorrect Channel Id" },
    { 'E', "Snapshot Request Already Active" },
    { 'Q', "Quota Exceeded" },
    { 'R', "Snapshot Not Yet Available" },
    { 'S', "Incorrect Session Id" },
    { 'U', "Unknown Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_reject_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_reject_reason_code, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_SIZE;
}

/* Reserved */
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_NAME        "Reserved"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_DESCRIPTION "Reserved byte"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_FILTER      "iexequities.deepplussnap.reserved"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_TYPE        FT_BYTES
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_DISPLAY     BASE_NONE
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_ENCODING    ENC_NA
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_SIZE        1

/* Reserved 1 */
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_NAME        "Reserved 1"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_DESCRIPTION "Reserved for future use"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_FILTER      "iexequities.deepplussnap.reserved1"
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_SIZE        1

static unsigned
parse_iexequities_deepplussnap_reserved_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_reserved_1, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_SIZE, IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_SIZE;
}

/* Retail Liquidity Indicator */
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_NAME        "Retail Liquidity Indicator"
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION "Retail Liquidity Indicator identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_FILTER      "iexequities.deepplussnap.retailliquidityindicator"
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE        1

static const value_string iexequities_deepplussnap_retail_liquidity_indicator_vals[] = {
    { ' ', "Not Applicable" },
    { 'A', "Buy Interest" },
    { 'B', "Sell Interest" },
    { 'C', "Buy And Sell Interest" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_retail_liquidity_indicator, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE, IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE;
}

/* Round Lot Size */
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_NAME        "Round Lot Size"
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_DESCRIPTION "Number of shares that represent a round lot"
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_FILTER      "iexequities.deepplussnap.roundlotsize"
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_SIZE        4

static unsigned
parse_iexequities_deepplussnap_round_lot_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_round_lot_size, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_SIZE;
}

/* Security Event */
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_NAME        "Security Event"
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_DESCRIPTION "Security event identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_FILTER      "iexequities.deepplussnap.securityevent"
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_SIZE        1

static const value_string iexequities_deepplussnap_security_event_vals[] = {
    { 'O', "Opening Process Complete" },
    { 'C', "Closing Process Complete" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_security_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_security_event, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_SIZE;
}

/* Send Time */
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_NAME        "Send Time"
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_DESCRIPTION "Send time of segment"
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_FILTER      "iexequities.deepplussnap.sendtime"
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_SIZE        8

static unsigned
parse_iexequities_deepplussnap_send_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_send_time, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_SIZE;
}

/* Session Id */
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_NAME        "Session Id"
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_DESCRIPTION "Session identifier from the Deep Plus feed IexTp header"
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_FILTER      "iexequities.deepplussnap.sessionid"
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_TYPE        FT_UINT32
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_SIZE        4

static unsigned
parse_iexequities_deepplussnap_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_session_id, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_SIZE;
}

/* Short Sale Price Test Status */
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_NAME        "Short Sale Price Test Status"
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION "Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_FILTER      "iexequities.deepplussnap.shortsalepriceteststatus"
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_TYPE        FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE        1

static const value_string iexequities_deepplussnap_short_sale_price_test_status_vals[] = {
    { 0, "Not In Effect" },
    { 1, "In Effect" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_short_sale_price_test_status, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE;
}

/* Side */
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_NAME        "Side"
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_DESCRIPTION "Side of order"
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_FILTER      "iexequities.deepplussnap.side"
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_SIDE_SIZE        1

static const value_string iexequities_deepplussnap_side_vals[] = {
    { '8', "Buy" },
    { '5', "Sell" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_side, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SIDE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SIDE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SIDE_SIZE;
}

/* Singleprice Cross Trade */
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_NAME        "Singleprice Cross Trade"
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_DESCRIPTION "Trade resulting from a single-price cross"
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_FILTER      "iexequities.deepplussnap.singlepricecrosstrade"
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_MASK        0x08

/* Size */
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_NAME        "Size"
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_DESCRIPTION "Quoted size"
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_FILTER      "iexequities.deepplussnap.size"
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SIZE_SIZE        4

static unsigned
parse_iexequities_deepplussnap_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_size, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SIZE_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SIZE_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SIZE_SIZE;
}

/* Snapshot Length */
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_NAME        "Snapshot Length"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_DESCRIPTION "Length in bytes of the complete Snapshot Response including the Snapshot Start message, all Snapshot Data messages, and the Snapshot End message"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_FILTER      "iexequities.deepplussnap.snapshotlength"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_SIZE        8

static unsigned
parse_iexequities_deepplussnap_snapshot_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_snapshot_length, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_SIZE;
}

/* Snapshot Sequence Number */
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_NAME        "Snapshot Sequence Number"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DESCRIPTION "Sequence at which the snapshot was created"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_FILTER      "iexequities.deepplussnap.snapshotsequencenumber"
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_deepplussnap_snapshot_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_snapshot_sequence_number, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE;
}

/* Stream Offset */
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_NAME        "Stream Offset"
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_DESCRIPTION "Byte offset of the data stream"
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_FILTER      "iexequities.deepplussnap.streamoffset"
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_SIZE        8

static unsigned
parse_iexequities_deepplussnap_stream_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_stream_offset, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_SIZE, IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_SIZE;
}

/* Symbol */
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_NAME        "Symbol"
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_DESCRIPTION "Security identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_FILTER      "iexequities.deepplussnap.symbol"
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_TYPE        FT_STRING
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_DISPLAY     BASE_NONE
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_SIZE        8

static unsigned
parse_iexequities_deepplussnap_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_symbol, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_SIZE;
}

/* System Event */
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_NAME        "System Event"
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_DESCRIPTION "System event identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_FILTER      "iexequities.deepplussnap.systemevent"
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_SIZE        1

static const value_string iexequities_deepplussnap_system_event_vals[] = {
    { 'O', "Start Of Messages" },
    { 'S', "Start Of System Hours" },
    { 'R', "Start Of Regular Market Hours" },
    { 'M', "End Of Regular Market Hours" },
    { 'E', "End Of System Hours" },
    { 'C', "End Of Messages" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_system_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_system_event, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_SIZE, IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_SIZE;
}

/* Test Security */
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_NAME        "Test Security"
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_DESCRIPTION "Symbol is a test security"
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_FILTER      "iexequities.deepplussnap.testsecurity"
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_MASK        0x80

/* Timestamp */
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_NAME        "Timestamp"
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_DESCRIPTION "Time stamp of the system event"
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_FILTER      "iexequities.deepplussnap.timestamp"
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_SIZE        8

static unsigned
parse_iexequities_deepplussnap_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_timestamp, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_SIZE, IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_SIZE;
}

/* Trade Id */
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_NAME        "Trade Id"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_DESCRIPTION "IEX Generated Identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_FILTER      "iexequities.deepplussnap.tradeid"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_TYPE        FT_UINT64
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_SIZE        8

static unsigned
parse_iexequities_deepplussnap_trade_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_trade_id, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_SIZE, IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_SIZE;
}

/* Trade Through Exempt */
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_NAME        "Trade Through Exempt"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_DESCRIPTION "Trade is not subject to Rule 611"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_FILTER      "iexequities.deepplussnap.tradethroughexempt"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_MASK        0x10

/* Trading Status */
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_NAME        "Trading Status"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_DESCRIPTION "Trading status identifier"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_FILTER      "iexequities.deepplussnap.tradingstatus"
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_SIZE        1

static const value_string iexequities_deepplussnap_trading_status_vals[] = {
    { 'H', "Trading Halted Across All Us Equity Markets" },
    { 'O', "Trading Halt Released Into An Order Acceptance Period On Iex" },
    { 'P', "Trading Paused And Order Acceptance Period On Iex" },
    { 'T', "Trading On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_deepplussnap_trading_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_trading_status, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_SIZE, IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_SIZE;
}

/* Version */
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_NAME        "Version"
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_DESCRIPTION "Version of transport specification"
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_FILTER      "iexequities.deepplussnap.version"
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_TYPE        FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_DISPLAY     BASE_DEC
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_MASK        0x0
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_VERSION_SIZE        1

static unsigned
parse_iexequities_deepplussnap_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_deepplussnap_version, tvb, offset, IEXEQUITIES_DEEPPLUSSNAP_VERSION_SIZE, IEXEQUITIES_DEEPPLUSSNAP_VERSION_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_VERSION_SIZE;
}

/* When Issued */
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_NAME        "When Issued"
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_DESCRIPTION "Symbol is a when issued security"
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_FILTER      "iexequities.deepplussnap.whenissued"
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_TYPE        FT_BOOLEAN
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_DISPLAY     8
#define IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_MASK        0x40

/*
 * IexEquities DeepPlus Structs
 */

/* Security Directory Flags */
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_NAME     "Security Directory Flags"
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_FILTER   "iexequities.deepplussnap.securitydirectoryflags"
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_MASK     0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_SIZE     1

static int * const iexequities_deepplussnap_security_directory_flags_fields[] = {
    &hf_iexequities_deepplussnap_test_security,
    &hf_iexequities_deepplussnap_when_issued,
    &hf_iexequities_deepplussnap_etp,
    NULL
};

static unsigned
parse_iexequities_deepplussnap_security_directory_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_deepplussnap_security_directory_flags,
        ett_iexequities_deepplussnap_security_directory_flags, iexequities_deepplussnap_security_directory_flags_fields, IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_SIZE;
}

/* Modify Flags */
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_NAME     "Modify Flags"
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_FILTER   "iexequities.deepplussnap.modifyflags"
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_MASK     0x0
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_SIZE     1

static int * const iexequities_deepplussnap_modify_flags_fields[] = {
    &hf_iexequities_deepplussnap_priority,
    NULL
};

static unsigned
parse_iexequities_deepplussnap_modify_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_deepplussnap_modify_flags,
        ett_iexequities_deepplussnap_modify_flags, iexequities_deepplussnap_modify_flags_fields, IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_SIZE;
}

/* Sale Condition Flags */
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_NAME     "Sale Condition Flags"
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_FILTER   "iexequities.deepplussnap.saleconditionflags"
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_MASK     0x0
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_SIZE     1

static int * const iexequities_deepplussnap_sale_condition_flags_fields[] = {
    &hf_iexequities_deepplussnap_intermarket_sweep,
    &hf_iexequities_deepplussnap_extended_hours,
    &hf_iexequities_deepplussnap_odd_lot,
    &hf_iexequities_deepplussnap_trade_through_exempt,
    &hf_iexequities_deepplussnap_singleprice_cross_trade,
    NULL
};

static unsigned
parse_iexequities_deepplussnap_sale_condition_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_deepplussnap_sale_condition_flags,
        ett_iexequities_deepplussnap_sale_condition_flags, iexequities_deepplussnap_sale_condition_flags_fields, IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_ENCODING);

    return offset + IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_iexequities_deepplussnap_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_snapshot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_error_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_snapshot_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_snapshot_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_iextp_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_snapshot_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_security_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_add_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_order_modify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_clear_book(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_deepplussnap_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_iexequities_deepplussnap_iex_tp_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t iex_tp_message_type);

/* Message Header */
static unsigned
dissect_iexequities_deepplussnap_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (iexequities_deepplussnap_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_iexequities_deepplussnap_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_iexequities_deepplussnap_message_length(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Snapshot Request Message */
static unsigned
dissect_iexequities_deepplussnap_snapshot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_authentication_token(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_channel_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_session_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_minimum_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Error Response Message */
static unsigned
dissect_iexequities_deepplussnap_error_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_reject_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Start Message */
static unsigned
dissect_iexequities_deepplussnap_snapshot_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_snapshot_length(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Data Message */
static unsigned
dissect_iexequities_deepplussnap_snapshot_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_iexequities_deepplussnap_iextp_header(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_iex_tp_message_block_length(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_iex_tp_message_length(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_iex_tp_message_type(tvb, pinfo, tree, offset);

    uint32_t iex_tp_message_type = tvb_get_uint8(tvb, start + 44);

    offset = dissect_iexequities_deepplussnap_iex_tp_message_data(tvb, pinfo, tree, offset, iex_tp_message_type);

    return offset;
}

/* Iextp Header */
static unsigned
dissect_iexequities_deepplussnap_iextp_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (iexequities_deepplussnap_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_iexequities_deepplussnap_iextp_header, &item, "Iextp Header");
    }

    unsigned start = offset;

    offset = parse_iexequities_deepplussnap_version(tvb, pinfo, group, offset);
    offset += IEXEQUITIES_DEEPPLUSSNAP_RESERVED_SIZE;
    offset = parse_iexequities_deepplussnap_message_protocol_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_channel_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_session_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_payload_length(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_message_count(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_stream_offset(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_first_message_sequence_number(tvb, pinfo, group, offset);
    offset = parse_iexequities_deepplussnap_send_time(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Snapshot End Message */
static unsigned
dissect_iexequities_deepplussnap_snapshot_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_snapshot_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message */
static unsigned
dissect_iexequities_deepplussnap_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_system_event(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);

    return offset;
}

/* Security Directory Message */
static unsigned
dissect_iexequities_deepplussnap_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_security_directory_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_adjusted_poc_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_luld_tier(tvb, pinfo, tree, offset);

    return offset;
}

/* Trading Status Message */
static unsigned
dissect_iexequities_deepplussnap_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_trading_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Liquidity Indicator Message */
static unsigned
dissect_iexequities_deepplussnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Operational Halt Status Message */
static unsigned
dissect_iexequities_deepplussnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_operational_halt_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Short Sale Price Test Status Message */
static unsigned
dissect_iexequities_deepplussnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_short_sale_price_test_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_detail(tvb, pinfo, tree, offset);

    return offset;
}

/* Security Event Message */
static unsigned
dissect_iexequities_deepplussnap_security_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_security_event(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_iexequities_deepplussnap_add_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_side(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_order_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Modify Message */
static unsigned
dissect_iexequities_deepplussnap_order_modify(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_modify_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_order_id_reference(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message */
static unsigned
dissect_iexequities_deepplussnap_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_reserved_1(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_order_id_reference(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_iexequities_deepplussnap_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_order_id_reference(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_iexequities_deepplussnap_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Break Message */
static unsigned
dissect_iexequities_deepplussnap_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Clear Book Message */
static unsigned
dissect_iexequities_deepplussnap_clear_book(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_deepplussnap_reserved_1(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_deepplussnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * IexEquities DeepPlus Parse Trees, a dispatch per distinct branch definition
 */

static const value_string iexequities_deepplussnap_messages[] = {
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST, "Snapshot Request Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ERROR_RESPONSE, "Error Response Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_START, "Snapshot Start Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA, "Snapshot Data Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_END, "Snapshot End Message" },
    { 0, NULL }
};

/* Message Data: dispatch on message_type */
static unsigned
dissect_iexequities_deepplussnap_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, iexequities_deepplussnap_messages, "Unknown (%u)"));

    switch (message_type) {
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST:
        return dissect_iexequities_deepplussnap_snapshot_request(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ERROR_RESPONSE:
        return dissect_iexequities_deepplussnap_error_response(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_START:
        return dissect_iexequities_deepplussnap_snapshot_start(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA:
        return dissect_iexequities_deepplussnap_snapshot_data(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_END:
        return dissect_iexequities_deepplussnap_snapshot_end(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string iexequities_deepplussnap_iex_tp_message_data_messages[] = {
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_EVENT, "Security Event Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ADD_ORDER, "Add Order Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_MODIFY, "Order Modify Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE, "Trade Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_CLEAR_BOOK, "Clear Book Message" },
    { 0, NULL }
};

/* Iex Tp Message Data: dispatch on iex_tp_message_type */
static unsigned
dissect_iexequities_deepplussnap_iex_tp_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t iex_tp_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, iex_tp_message_type, iexequities_deepplussnap_iex_tp_message_data_messages, "Unknown (%u)"));

    switch (iex_tp_message_type) {
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_iexequities_deepplussnap_system_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY:
        return dissect_iexequities_deepplussnap_security_directory(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS:
        return dissect_iexequities_deepplussnap_trading_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR:
        return dissect_iexequities_deepplussnap_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS:
        return dissect_iexequities_deepplussnap_operational_halt_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS:
        return dissect_iexequities_deepplussnap_short_sale_price_test_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_EVENT:
        return dissect_iexequities_deepplussnap_security_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ADD_ORDER:
        return dissect_iexequities_deepplussnap_add_order(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_MODIFY:
        return dissect_iexequities_deepplussnap_order_modify(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_iexequities_deepplussnap_order_delete(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_iexequities_deepplussnap_order_executed(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE:
        return dissect_iexequities_deepplussnap_trade(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK:
        return dissect_iexequities_deepplussnap_trade_break(tvb, pinfo, tree, offset);
    case IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_CLEAR_BOOK:
        return dissect_iexequities_deepplussnap_clear_book(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
iexequities_deepplussnap_show(uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST:
        return iexequities_deepplussnap_show_application_messages;
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_ERROR_RESPONSE:
        return iexequities_deepplussnap_show_application_messages;
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_START:
        return iexequities_deepplussnap_show_application_messages;
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA:
        return iexequities_deepplussnap_show_application_messages;
    case IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_SNAPSHOT_END:
        return iexequities_deepplussnap_show_application_messages;
    }

    return true;
}

typedef struct iexequities_deepplussnap_parse iexequities_deepplussnap_parse;

struct iexequities_deepplussnap_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
};

static const iexequities_deepplussnap_parse iexequities_deepplussnap_parse_v106 = { iexequities_deepplussnap_messages, dissect_iexequities_deepplussnap_message_data };

/* Parse tree of the selected version */
static const iexequities_deepplussnap_parse *
iexequities_deepplussnap_parse_for(int version)
{
    switch (version) {
    default:
        return &iexequities_deepplussnap_parse_v106;
    }
}

/* IexEquities DeepPlus message size adjusts the declared length */
#define IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_iexequities_deepplussnap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const iexequities_deepplussnap_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = iexequities_deepplussnap_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT, ett_iexequities_deepplussnap_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_iexequities_deepplussnap_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_iexequities_deepplussnap_length);
    }

    return message_length + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_iexequities_deepplussnap_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const iexequities_deepplussnap_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_letohs(tvb, offset) + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_iexequities_deepplussnap_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_iexequities_deepplussnap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_iexequities_deepplussnap, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_iexequities_deepplussnap);

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = iexequities_deepplussnap_version(seconds);

    proto_item_append_text(item, " %s", iexequities_deepplussnap_version_name(version));

    const iexequities_deepplussnap_parse *parse = iexequities_deepplussnap_parse_for(version);
    unsigned position = 0;

    position = dissect_iexequities_deepplussnap_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SIZE 3

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
iexequities_deepplussnap_heur_port(packet_info *pinfo)
{
    return value_is_in_range(iexequities_deepplussnap_pref_ports, pinfo->destport)
        || value_is_in_range(iexequities_deepplussnap_pref_ports, pinfo->srcport);
}

/* The first frame's declared length fits the stream */
static bool
iexequities_deepplussnap_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_letohs(tvb, 0) + IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_ADJUSTMENT);

    return frame >= IEXEQUITIES_DEEPPLUSSNAP_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Does the frame pass every test of Packet? */
static bool
iexequities_deepplussnap_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!iexequities_deepplussnap_heur_port(pinfo)) {
        return false;
    }

    if (!iexequities_deepplussnap_heur_frame(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on */
static bool
dissect_iexequities_deepplussnap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SIZE) {
        return false;
    }

    if (!iexequities_deepplussnap_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_iexequities_deepplussnap(tvb, pinfo, tree, data);

    return true;
}

/*
 * IexEquities DeepPlus Registration
 */

void
proto_register_iexequities_deepplussnap(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_iexequities_deepplussnap_adjusted_poc_price,
            { IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_DISPLAY,
              CF_FUNC(iexequities_deepplussnap_format_decimal_4_64),
              IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_ADJUSTED_POC_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_authentication_token,
            { IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_AUTHENTICATION_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_channel_id,
            { IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_CHANNEL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_detail,
            { IEXEQUITIES_DEEPPLUSSNAP_DETAIL_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_DETAIL_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_DETAIL_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_DETAIL_DISPLAY,
              VALS(iexequities_deepplussnap_detail_vals),
              IEXEQUITIES_DEEPPLUSSNAP_DETAIL_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_DETAIL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_first_message_sequence_number,
            { IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_iex_tp_message_block_length,
            { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_iex_tp_message_length,
            { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_iex_tp_message_type,
            { IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_DISPLAY,
              VALS(iexequities_deepplussnap_iex_tp_message_type_vals),
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_IEX_TP_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_luld_tier,
            { IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_DISPLAY,
              VALS(iexequities_deepplussnap_luld_tier_vals),
              IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_LULD_TIER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_message_count,
            { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_message_length,
            { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_message_protocol_id,
            { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_PROTOCOL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_message_type,
            { IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_DISPLAY,
              VALS(iexequities_deepplussnap_message_type_vals),
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_minimum_sequence_number,
            { IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_MINIMUM_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_operational_halt_status,
            { IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_DISPLAY,
              VALS(iexequities_deepplussnap_operational_halt_status_vals),
              IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_OPERATIONAL_HALT_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_order_id,
            { IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_order_id_reference,
            { IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_ORDER_ID_REFERENCE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_payload_length,
            { IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_PAYLOAD_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_price,
            { IEXEQUITIES_DEEPPLUSSNAP_PRICE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_PRICE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_PRICE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_PRICE_DISPLAY,
              CF_FUNC(iexequities_deepplussnap_format_decimal_4_64),
              IEXEQUITIES_DEEPPLUSSNAP_PRICE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_reason,
            { IEXEQUITIES_DEEPPLUSSNAP_REASON_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_REASON_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_REASON_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_REASON_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_REASON_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_REASON_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_reject_reason_code,
            { IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_DISPLAY,
              VALS(iexequities_deepplussnap_reject_reason_code_vals),
              IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_REJECT_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_reserved,
            { IEXEQUITIES_DEEPPLUSSNAP_RESERVED_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_reserved_1,
            { IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_RESERVED_1_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_retail_liquidity_indicator,
            { IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_DISPLAY,
              VALS(iexequities_deepplussnap_retail_liquidity_indicator_vals),
              IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_round_lot_size,
            { IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_ROUND_LOT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_security_event,
            { IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_DISPLAY,
              VALS(iexequities_deepplussnap_security_event_vals),
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_send_time,
            { IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SEND_TIME_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_session_id,
            { IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SESSION_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_short_sale_price_test_status,
            { IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY,
              VALS(iexequities_deepplussnap_short_sale_price_test_status_vals),
              IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_side,
            { IEXEQUITIES_DEEPPLUSSNAP_SIDE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SIDE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SIDE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SIDE_DISPLAY,
              VALS(iexequities_deepplussnap_side_vals),
              IEXEQUITIES_DEEPPLUSSNAP_SIDE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_size,
            { IEXEQUITIES_DEEPPLUSSNAP_SIZE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SIZE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SIZE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SIZE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_snapshot_length,
            { IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_snapshot_sequence_number,
            { IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_stream_offset,
            { IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_STREAM_OFFSET_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_symbol,
            { IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_system_event,
            { IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_DISPLAY,
              VALS(iexequities_deepplussnap_system_event_vals),
              IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SYSTEM_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_timestamp,
            { IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_trade_id,
            { IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_trading_status,
            { IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_DISPLAY,
              VALS(iexequities_deepplussnap_trading_status_vals),
              IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_TRADING_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_version,
            { IEXEQUITIES_DEEPPLUSSNAP_VERSION_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_VERSION_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_VERSION_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_VERSION_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_VERSION_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_VERSION_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_iexequities_deepplussnap_etp,
            { IEXEQUITIES_DEEPPLUSSNAP_ETP_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ETP_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ETP_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ETP_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_ETP_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_ETP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_extended_hours,
            { IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_EXTENDED_HOURS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_intermarket_sweep,
            { IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_INTERMARKET_SWEEP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_odd_lot,
            { IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_ODD_LOT_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_deepplussnap_priority,
            { IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_PRIORITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_singleprice_cross_trade,
            { IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_SINGLEPRICE_CROSS_TRADE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_test_security,
            { IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_TEST_SECURITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_trade_through_exempt,
            { IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_TRADE_THROUGH_EXEMPT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_deepplussnap_when_issued,
            { IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_MASK,
              IEXEQUITIES_DEEPPLUSSNAP_WHEN_ISSUED_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_iexequities_deepplussnap_security_directory_flags,
            { IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SECURITY_DIRECTORY_FLAGS_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_deepplussnap_modify_flags,
            { IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_MODIFY_FLAGS_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_deepplussnap_sale_condition_flags,
            { IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_NAME,
              IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_TYPE,
              IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_DEEPPLUSSNAP_SALE_CONDITION_FLAGS_MASK,
              NULL,
              HFILL } },
    };

    static int *ett[] = {
        &ett_iexequities_deepplussnap,
        &ett_iexequities_deepplussnap_header,
        &ett_iexequities_deepplussnap_message,
        &ett_iexequities_deepplussnap_security_directory_flags,
        &ett_iexequities_deepplussnap_modify_flags,
        &ett_iexequities_deepplussnap_sale_condition_flags,
        &ett_iexequities_deepplussnap_message_header,
        &ett_iexequities_deepplussnap_iextp_header,
    };

    static ei_register_info ei[] = {
        { &ei_iexequities_deepplussnap_length,
            { IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_FILTER,
              IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_GROUP,
              IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_SEVERITY,
              IEXEQUITIES_DEEPPLUSSNAP_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_iexequities_deepplussnap = proto_register_protocol(IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_NAME, IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_SHORT, IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_FILTER);

    proto_register_field_array(proto_iexequities_deepplussnap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_iexequities_deepplussnap = expert_register_protocol(proto_iexequities_deepplussnap);
    expert_register_field_array(expert_iexequities_deepplussnap, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_iexequities_deepplussnap, NULL);

    prefs_register_enum_preference(
        preferences,
        IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_NAME,
        IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_TITLE,
        IEXEQUITIES_DEEPPLUSSNAP_VERSION_PREFERENCE_DESCRIPTION,
        &iexequities_deepplussnap_pref_version,
        iexequities_deepplussnap_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_NAME,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_TITLE,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &iexequities_deepplussnap_show_headers);

    prefs_register_bool_preference(
        preferences,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        IEXEQUITIES_DEEPPLUSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &iexequities_deepplussnap_show_application_messages);

    prefs_register_uint_preference(
        preferences,
        IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_NAME,
        IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_TITLE,
        IEXEQUITIES_DEEPPLUSSNAP_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &iexequities_deepplussnap_pref_decimal_places);

    range_convert_str(
        wmem_epan_scope(),
        &iexequities_deepplussnap_pref_ports,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_DEFAULT,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_NAME,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_TITLE,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_DESCRIPTION,
        &iexequities_deepplussnap_pref_ports,
        IEXEQUITIES_DEEPPLUSSNAP_PORTS_PREFERENCE_MAXIMUM);

    iexequities_deepplussnap_handle = register_dissector(IEXEQUITIES_DEEPPLUSSNAP_PROTOCOL_FILTER, dissect_iexequities_deepplussnap, proto_iexequities_deepplussnap);
}

void
proto_reg_handoff_iexequities_deepplussnap(void)
{
    heur_dissector_add("tcp", dissect_iexequities_deepplussnap_heur, "IEX DEEP+ SNAP over TCP",
        "iexequities_deepplussnap_tcp", proto_iexequities_deepplussnap, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", iexequities_deepplussnap_handle);
}
