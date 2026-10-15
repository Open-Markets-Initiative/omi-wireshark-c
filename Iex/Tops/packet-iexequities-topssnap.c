/* packet-iexequities-topssnap.c
 * Routines for IEX TOPS SNAP dissection
 *
 * Aggregated protocol versions: 1.6
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Iex.IexEquities.Tops.Snap.v1.6
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

void proto_register_iexequities_topssnap(void);
void proto_reg_handoff_iexequities_topssnap(void);

static dissector_handle_t iexequities_topssnap_handle;

static int proto_iexequities_topssnap;

/*
 * IexEquities Tops Protocol
 */

#define IEXEQUITIES_TOPSSNAP_PROTOCOL_NAME "IEX TOPS SNAP"
#define IEXEQUITIES_TOPSSNAP_PROTOCOL_SHORT "IEXEQUITIES.TOPSSNAP"
#define IEXEQUITIES_TOPSSNAP_PROTOCOL_FILTER "iexequities.topssnap"

/*
 * IexEquities Tops Header
 */

#define IEXEQUITIES_TOPSSNAP_HEADER_SIZE 3 /* Message */

/*
 * IexEquities Tops Field Handles
 */

static int hf_iexequities_topssnap_adjusted_poc_price;
static int hf_iexequities_topssnap_ask_price;
static int hf_iexequities_topssnap_ask_size;
static int hf_iexequities_topssnap_auction_book_clearing_price;
static int hf_iexequities_topssnap_auction_type;
static int hf_iexequities_topssnap_authentication_token;
static int hf_iexequities_topssnap_bid_price;
static int hf_iexequities_topssnap_bid_size;
static int hf_iexequities_topssnap_channel_id;
static int hf_iexequities_topssnap_collar_reference_price;
static int hf_iexequities_topssnap_detail;
static int hf_iexequities_topssnap_etp;
static int hf_iexequities_topssnap_extended_hours;
static int hf_iexequities_topssnap_extension_number;
static int hf_iexequities_topssnap_first_message_sequence_number;
static int hf_iexequities_topssnap_iex_tp_message_block_length;
static int hf_iexequities_topssnap_iex_tp_message_length;
static int hf_iexequities_topssnap_iex_tp_message_type;
static int hf_iexequities_topssnap_imbalance_shares;
static int hf_iexequities_topssnap_imbalance_side;
static int hf_iexequities_topssnap_indicative_clearing_price;
static int hf_iexequities_topssnap_intermarket_sweep;
static int hf_iexequities_topssnap_lower_auction_collar;
static int hf_iexequities_topssnap_luld_tier;
static int hf_iexequities_topssnap_market_session;
static int hf_iexequities_topssnap_message_count;
static int hf_iexequities_topssnap_message_length;
static int hf_iexequities_topssnap_message_protocol_id;
static int hf_iexequities_topssnap_message_type;
static int hf_iexequities_topssnap_minimum_sequence_number;
static int hf_iexequities_topssnap_odd_lot;
static int hf_iexequities_topssnap_official_price;
static int hf_iexequities_topssnap_operational_halt_status;
static int hf_iexequities_topssnap_paired_shares;
static int hf_iexequities_topssnap_payload_length;
static int hf_iexequities_topssnap_price;
static int hf_iexequities_topssnap_price_type;
static int hf_iexequities_topssnap_quote_update_flags;
static int hf_iexequities_topssnap_reason;
static int hf_iexequities_topssnap_reference_price;
static int hf_iexequities_topssnap_reject_reason_code;
static int hf_iexequities_topssnap_reserved;
static int hf_iexequities_topssnap_retail_liquidity_indicator;
static int hf_iexequities_topssnap_round_lot_size;
static int hf_iexequities_topssnap_sale_condition_flags;
static int hf_iexequities_topssnap_scheduled_auction_time;
static int hf_iexequities_topssnap_security_directory_flags;
static int hf_iexequities_topssnap_send_time;
static int hf_iexequities_topssnap_session_id;
static int hf_iexequities_topssnap_short_sale_price_test_status;
static int hf_iexequities_topssnap_singleprice_cross_trade;
static int hf_iexequities_topssnap_size;
static int hf_iexequities_topssnap_snapshot_length;
static int hf_iexequities_topssnap_snapshot_sequence_number;
static int hf_iexequities_topssnap_stream_offset;
static int hf_iexequities_topssnap_symbol;
static int hf_iexequities_topssnap_symbol_availability;
static int hf_iexequities_topssnap_system_event;
static int hf_iexequities_topssnap_test_security;
static int hf_iexequities_topssnap_timestamp;
static int hf_iexequities_topssnap_trade_id;
static int hf_iexequities_topssnap_trade_through_exempt;
static int hf_iexequities_topssnap_trading_status;
static int hf_iexequities_topssnap_upper_auction_collar;
static int hf_iexequities_topssnap_version;
static int hf_iexequities_topssnap_when_issued;

/*
 * IexEquities Tops Subtrees
 */

static int ett_iexequities_topssnap;
static int ett_iexequities_topssnap_header;
static int ett_iexequities_topssnap_message;
static int ett_iexequities_topssnap_security_directory_flags;
static int ett_iexequities_topssnap_quote_update_flags;
static int ett_iexequities_topssnap_sale_condition_flags;
static int ett_iexequities_topssnap_message_header;
static int ett_iexequities_topssnap_iextp_header;

/*
 * IexEquities Tops Expert Information
 */

/* Message length does not account for the parsed fields */
#define IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_FILTER "iexequities.topssnap.length.invalid"
#define IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_GROUP PI_MALFORMED
#define IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_SEVERITY PI_ERROR
#define IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_iexequities_topssnap_length;

/*
 * IexEquities Tops Preferences
 */

#define IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_NAME "version"
#define IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_TITLE "Protocol version"
#define IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define IEXEQUITIES_TOPSSNAP_VERSION_AUTOMATIC 0
#define IEXEQUITIES_TOPSSNAP_VERSION_1_6     1

static const enum_val_t iexequities_topssnap_version_vals[] = {
    { "automatic", "Automatic (by send time)", IEXEQUITIES_TOPSSNAP_VERSION_AUTOMATIC },
    { "v1.6", "1.6", IEXEQUITIES_TOPSSNAP_VERSION_1_6 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
iexequities_topssnap_version_name(int version)
{
    switch (version) {
    case IEXEQUITIES_TOPSSNAP_VERSION_1_6:
        return "1.6";
    }

    return "";
}

static int iexequities_topssnap_pref_version = IEXEQUITIES_TOPSSNAP_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */

/* Show preferences, one per message and struct */
#define IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

static bool iexequities_topssnap_show_headers = true;
static bool iexequities_topssnap_show_application_messages = true;

/* Decimal places shown, the wire precision by default */
#define IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_NAME "decimal.places"
#define IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned iexequities_topssnap_pref_decimal_places = 4;

/* Ports the feed arrives on, assigned per deployment */
#define IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_NAME "ports"
#define IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_TITLE "Ports"
#define IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_DEFAULT "11380,33380"
#define IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *iexequities_topssnap_pref_ports;

/*
 * IexEquities Tops Methods
 */

/* Select the protocol version, this protocol has one */
static int
iexequities_topssnap_version(uint64_t seconds _U_)
{
    return IEXEQUITIES_TOPSSNAP_VERSION_1_6;
}

/* Cap the fraction at the preferred decimal places */
static void
iexequities_topssnap_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = iexequities_topssnap_pref_decimal_places;

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
iexequities_topssnap_format_decimal_4_64(char *buf, uint64_t raw)
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

    iexequities_topssnap_decimal_places(buf);
}

/*
 * IexEquities Tops Fields
 */

/* Adjusted Poc Price */
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_NAME        "Adjusted Poc Price"
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_DESCRIPTION "Corporate action adjusted previous official closing price"
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_FILTER      "iexequities.topssnap.adjustedpocprice"
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_adjusted_poc_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_adjusted_poc_price, tvb, offset, IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_SIZE;
}

/* Ask Price */
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_NAME        "Ask Price"
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_DESCRIPTION "Best quoted ask price"
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_FILTER      "iexequities.topssnap.askprice"
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_ASK_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_ask_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_ask_price, tvb, offset, IEXEQUITIES_TOPSSNAP_ASK_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_ASK_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_ASK_PRICE_SIZE;
}

/* Ask Size */
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_NAME        "Ask Size"
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_DESCRIPTION "Aggregate quoted best ask size"
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_FILTER      "iexequities.topssnap.asksize"
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_ASK_SIZE_SIZE        4

static unsigned
parse_iexequities_topssnap_ask_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_ask_size, tvb, offset, IEXEQUITIES_TOPSSNAP_ASK_SIZE_SIZE, IEXEQUITIES_TOPSSNAP_ASK_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_ASK_SIZE_SIZE;
}

/* Auction Book Clearing Price */
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_NAME        "Auction Book Clearing Price"
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_DESCRIPTION "Clearing price using orders on the Auction Book"
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_FILTER      "iexequities.topssnap.auctionbookclearingprice"
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_auction_book_clearing_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_auction_book_clearing_price, tvb, offset, IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_SIZE;
}

/* Auction Type */
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_NAME        "Auction Type"
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_DESCRIPTION "Auction type identifier"
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_FILTER      "iexequities.topssnap.auctiontype"
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_SIZE        1

static const value_string iexequities_topssnap_auction_type_vals[] = {
    { 'O', "Opening Auction" },
    { 'C', "Closing Auction" },
    { 'I', "Ipo Auction" },
    { 'H', "Halt Auction" },
    { 'V', "Volatility Auction" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_auction_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_auction_type, tvb, offset, IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_SIZE, IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_SIZE;
}

/* Authentication Token */
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_NAME        "Authentication Token"
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_DESCRIPTION "Token supplied by Iex Market Ops, left justified and space padded on the right"
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_FILTER      "iexequities.topssnap.authenticationtoken"
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_TYPE        FT_STRING
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_SIZE        40

static unsigned
parse_iexequities_topssnap_authentication_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_authentication_token, tvb, offset, IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_SIZE, IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_SIZE;
}

/* Bid Price */
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_NAME        "Bid Price"
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_DESCRIPTION "Best quoted bid price"
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_FILTER      "iexequities.topssnap.bidprice"
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_BID_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_bid_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_bid_price, tvb, offset, IEXEQUITIES_TOPSSNAP_BID_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_BID_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_BID_PRICE_SIZE;
}

/* Bid Size */
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_NAME        "Bid Size"
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_DESCRIPTION "Aggregate quoted best bid size"
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_FILTER      "iexequities.topssnap.bidsize"
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_BID_SIZE_SIZE        4

static unsigned
parse_iexequities_topssnap_bid_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_bid_size, tvb, offset, IEXEQUITIES_TOPSSNAP_BID_SIZE_SIZE, IEXEQUITIES_TOPSSNAP_BID_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_BID_SIZE_SIZE;
}

/* Channel Id */
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_NAME        "Channel Id"
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_DESCRIPTION "Channel identifier from the Tops feed IexTp header"
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_FILTER      "iexequities.topssnap.channelid"
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_CHANNEL_ID_SIZE        4

static unsigned
parse_iexequities_topssnap_channel_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_channel_id, tvb, offset, IEXEQUITIES_TOPSSNAP_CHANNEL_ID_SIZE, IEXEQUITIES_TOPSSNAP_CHANNEL_ID_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_CHANNEL_ID_SIZE;
}

/* Collar Reference Price */
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_NAME        "Collar Reference Price"
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_DESCRIPTION "Reference priced used for the auction collar, if any"
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_FILTER      "iexequities.topssnap.collarreferenceprice"
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_collar_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_collar_reference_price, tvb, offset, IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_SIZE;
}

/* Detail */
#define IEXEQUITIES_TOPSSNAP_DETAIL_NAME        "Detail"
#define IEXEQUITIES_TOPSSNAP_DETAIL_DESCRIPTION "Detail of the Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_TOPSSNAP_DETAIL_FILTER      "iexequities.topssnap.detail"
#define IEXEQUITIES_TOPSSNAP_DETAIL_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_DETAIL_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_DETAIL_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_DETAIL_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_DETAIL_SIZE        1

static const value_string iexequities_topssnap_detail_vals[] = {
    { ' ', "No Price Test In Place" },
    { 'A', "Activated" },
    { 'C', "Continued" },
    { 'D', "Deactivated" },
    { 'N', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_detail(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_detail, tvb, offset, IEXEQUITIES_TOPSSNAP_DETAIL_SIZE, IEXEQUITIES_TOPSSNAP_DETAIL_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_DETAIL_SIZE;
}

/* Etp */
#define IEXEQUITIES_TOPSSNAP_ETP_NAME        "Etp"
#define IEXEQUITIES_TOPSSNAP_ETP_DESCRIPTION "Symbol is an ETP"
#define IEXEQUITIES_TOPSSNAP_ETP_FILTER      "iexequities.topssnap.etp"
#define IEXEQUITIES_TOPSSNAP_ETP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_ETP_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_ETP_MASK        0x20

/* Extended Hours */
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_NAME        "Extended Hours"
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_DESCRIPTION "Extended Hours Trade"
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_FILTER      "iexequities.topssnap.extendedhours"
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_MASK        0x40

/* Extension Number */
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_NAME        "Extension Number"
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_DESCRIPTION "Number of extensions an auction received"
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_FILTER      "iexequities.topssnap.extensionnumber"
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_SIZE        1

static unsigned
parse_iexequities_topssnap_extension_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_extension_number, tvb, offset, IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_SIZE, IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_SIZE;
}

/* First Message Sequence Number */
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME        "First Message Sequence Number"
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION "Sequence of the first message in the segment"
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER      "iexequities.topssnap.firstmessagesequencenumber"
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_topssnap_first_message_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_first_message_sequence_number, tvb, offset, IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE;
}

/* Iex Tp Message Block Length */
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_NAME        "Iex Tp Message Block Length"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DESCRIPTION "Length in bytes of the IexTp message block that follows this field: the IexTp Message Length field and the message"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_FILTER      "iexequities.topssnap.iextpmessageblocklength"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE        2

static unsigned
parse_iexequities_topssnap_iex_tp_message_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_iex_tp_message_block_length, tvb, offset, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_SIZE;
}

/* Iex Tp Message Length */
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_NAME        "Iex Tp Message Length"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_DESCRIPTION "Length of the wrapped Tops message in bytes not including this field"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_FILTER      "iexequities.topssnap.iextpmessagelength"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_iexequities_topssnap_iex_tp_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_iex_tp_message_length, tvb, offset, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_SIZE;
}

/* Iex Tp Message Type values the dispatch switches on */
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT                 'S'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY           'D'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS               'H'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR   'I'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS      'O'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS 'P'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_QUOTE_UPDATE                 'Q'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_REPORT                 'T'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OFFICIAL_PRICE               'X'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK                  'B'
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_AUCTION_INFORMATION          'A'

/* Iex Tp Message Type */
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_NAME        "Iex Tp Message Type"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_DESCRIPTION "Code identifying the wrapped Tops message type"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_FILTER      "iexequities.topssnap.iextpmessagetype"
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SIZE        1

static const value_string iexequities_topssnap_iex_tp_message_type_vals[] = {
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OFFICIAL_PRICE, "Official Price Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_AUCTION_INFORMATION, "Auction Information Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_iex_tp_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_iex_tp_message_type, tvb, offset, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SIZE, IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SIZE;
}

/* Imbalance Shares */
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_NAME        "Imbalance Shares"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_DESCRIPTION "Number of unpaired shares at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_FILTER      "iexequities.topssnap.imbalanceshares"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_SIZE        4

static unsigned
parse_iexequities_topssnap_imbalance_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_imbalance_shares, tvb, offset, IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_SIZE, IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_SIZE;
}

/* Imbalance Side */
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_NAME        "Imbalance Side"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_DESCRIPTION "Side of the unpaired shares at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_FILTER      "iexequities.topssnap.imbalanceside"
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_SIZE        1

static const value_string iexequities_topssnap_imbalance_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'N', "None" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_imbalance_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_imbalance_side, tvb, offset, IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_SIZE, IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_SIZE;
}

/* Indicative Clearing Price */
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_NAME        "Indicative Clearing Price"
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_DESCRIPTION "Clearing price using Eligible Auction Orders"
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_FILTER      "iexequities.topssnap.indicativeclearingprice"
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_indicative_clearing_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_indicative_clearing_price, tvb, offset, IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_SIZE;
}

/* Intermarket Sweep */
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_NAME        "Intermarket Sweep"
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_DESCRIPTION "Intermarket Sweep Order"
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_FILTER      "iexequities.topssnap.intermarketsweep"
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_MASK        0x80

/* Lower Auction Collar */
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_NAME        "Lower Auction Collar"
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_DESCRIPTION "Lower threshold price of the auction collar, if any"
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_FILTER      "iexequities.topssnap.lowerauctioncollar"
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_SIZE        8

static unsigned
parse_iexequities_topssnap_lower_auction_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_lower_auction_collar, tvb, offset, IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_SIZE, IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_SIZE;
}

/* Luld Tier */
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_NAME        "Luld Tier"
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_DESCRIPTION "Indicates which Limit Up-Limit Down price band calculation parameter is to be used"
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_FILTER      "iexequities.topssnap.luldtier"
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_TYPE        FT_UINT8
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_LULD_TIER_SIZE        1

static const value_string iexequities_topssnap_luld_tier_vals[] = {
    { 0, "Not Applicable" },
    { 1, "Tier 1 Nms Stock" },
    { 2, "Tier 2 Nms Stock" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_luld_tier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_luld_tier, tvb, offset, IEXEQUITIES_TOPSSNAP_LULD_TIER_SIZE, IEXEQUITIES_TOPSSNAP_LULD_TIER_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_LULD_TIER_SIZE;
}

/* Market Session */
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_NAME        "Market Session"
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_DESCRIPTION "Market Session Flag"
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_FILTER      "iexequities.topssnap.marketsession"
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_MARKET_SESSION_MASK        0x40

/* Message Count */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_NAME        "Message Count"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_DESCRIPTION "Number of messages in the payload"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_FILTER      "iexequities.topssnap.messagecount"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_SIZE        2

static unsigned
parse_iexequities_topssnap_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_message_count, tvb, offset, IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_SIZE, IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_SIZE;
}

/* Message Length */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_NAME        "Message Length"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_DESCRIPTION "Length of message in bytes not including this field"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_FILTER      "iexequities.topssnap.messagelength"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_iexequities_topssnap_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_message_length, tvb, offset, IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_SIZE, IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_SIZE;
}

/* Message Protocol Id */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_NAME        "Message Protocol Id"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_DESCRIPTION "Unique identifier of the higher layer protocol"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_FILTER      "iexequities.topssnap.messageprotocolid"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_SIZE        2

static unsigned
parse_iexequities_topssnap_message_protocol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_message_protocol_id, tvb, offset, IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_SIZE, IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_SIZE;
}

/* Message Type values the dispatch switches on */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST 'r'
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ERROR_RESPONSE   'e'
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_START   's'
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA    'd'
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_END     'x'

/* Message Type */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_NAME        "Message Type"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_DESCRIPTION "Code identifying this message type"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_FILTER      "iexequities.topssnap.messagetype"
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SIZE        1

static const value_string iexequities_topssnap_message_type_vals[] = {
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST, "Snapshot Request Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ERROR_RESPONSE, "Error Response Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_START, "Snapshot Start Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA, "Snapshot Data Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_END, "Snapshot End Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_message_type, tvb, offset, IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SIZE, IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SIZE;
}

/* Minimum Sequence Number */
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_NAME        "Minimum Sequence Number"
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_DESCRIPTION "Minimum sequence number useable by the client, zero returns the latest snapshot available"
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_FILTER      "iexequities.topssnap.minimumsequencenumber"
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_topssnap_minimum_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_minimum_sequence_number, tvb, offset, IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_SIZE;
}

/* Odd Lot */
#define IEXEQUITIES_TOPSSNAP_ODD_LOT_NAME    "Odd Lot"
#define IEXEQUITIES_TOPSSNAP_ODD_LOT_FILTER  "iexequities.topssnap.oddlot"
#define IEXEQUITIES_TOPSSNAP_ODD_LOT_TYPE    FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_ODD_LOT_DISPLAY 8
#define IEXEQUITIES_TOPSSNAP_ODD_LOT_MASK    0x20

/* Official Price */
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_NAME        "Official Price"
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_DESCRIPTION "Official opening or closing price, as specified"
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_FILTER      "iexequities.topssnap.officialprice"
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_official_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_official_price, tvb, offset, IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_SIZE;
}

/* Operational Halt Status */
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_NAME        "Operational Halt Status"
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_DESCRIPTION "Operational halt status identifier"
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_FILTER      "iexequities.topssnap.operationalhaltstatus"
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_SIZE        1

static const value_string iexequities_topssnap_operational_halt_status_vals[] = {
    { 'O', "Iex Specific Operational Trading Halt" },
    { 'N', "Not Operationally Halted On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_operational_halt_status, tvb, offset, IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_SIZE, IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_SIZE;
}

/* Paired Shares */
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_NAME        "Paired Shares"
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_DESCRIPTION "Number of shares paired at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_FILTER      "iexequities.topssnap.pairedshares"
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_SIZE        4

static unsigned
parse_iexequities_topssnap_paired_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_paired_shares, tvb, offset, IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_SIZE, IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_SIZE;
}

/* Payload Length */
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_NAME        "Payload Length"
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_DESCRIPTION "Byte length of the payload"
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_FILTER      "iexequities.topssnap.payloadlength"
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_SIZE        2

static unsigned
parse_iexequities_topssnap_payload_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_payload_length, tvb, offset, IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_SIZE, IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_SIZE;
}

/* Price */
#define IEXEQUITIES_TOPSSNAP_PRICE_NAME        "Price"
#define IEXEQUITIES_TOPSSNAP_PRICE_DESCRIPTION "Trade price"
#define IEXEQUITIES_TOPSSNAP_PRICE_FILTER      "iexequities.topssnap.price"
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_price, tvb, offset, IEXEQUITIES_TOPSSNAP_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_PRICE_SIZE;
}

/* Price Type */
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_NAME        "Price Type"
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_DESCRIPTION "Price type identifier"
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_FILTER      "iexequities.topssnap.pricetype"
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_PRICE_TYPE_SIZE        1

static const value_string iexequities_topssnap_price_type_vals[] = {
    { 'Q', "Iex Official Opening Price" },
    { 'M', "Iex Official Closing Price" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_price_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_price_type, tvb, offset, IEXEQUITIES_TOPSSNAP_PRICE_TYPE_SIZE, IEXEQUITIES_TOPSSNAP_PRICE_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_PRICE_TYPE_SIZE;
}

/* Reason */
#define IEXEQUITIES_TOPSSNAP_REASON_NAME        "Reason"
#define IEXEQUITIES_TOPSSNAP_REASON_DESCRIPTION "Reason for the trading status change"
#define IEXEQUITIES_TOPSSNAP_REASON_FILTER      "iexequities.topssnap.reason"
#define IEXEQUITIES_TOPSSNAP_REASON_TYPE        FT_STRING
#define IEXEQUITIES_TOPSSNAP_REASON_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPSSNAP_REASON_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_REASON_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_REASON_SIZE        4

static unsigned
parse_iexequities_topssnap_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_reason, tvb, offset, IEXEQUITIES_TOPSSNAP_REASON_SIZE, IEXEQUITIES_TOPSSNAP_REASON_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_REASON_SIZE;
}

/* Reference Price */
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_NAME        "Reference Price"
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_DESCRIPTION "Clearing price at or within the Reference Price Range using orders on the Auction Book"
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_FILTER      "iexequities.topssnap.referenceprice"
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_SIZE        8

static unsigned
parse_iexequities_topssnap_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_reference_price, tvb, offset, IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_SIZE, IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_SIZE;
}

/* Reject Reason Code */
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_NAME        "Reject Reason Code"
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_DESCRIPTION "Reason the Snapshot Request was rejected"
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_FILTER      "iexequities.topssnap.rejectreasoncode"
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_SIZE        1

static const value_string iexequities_topssnap_reject_reason_code_vals[] = {
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
parse_iexequities_topssnap_reject_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_reject_reason_code, tvb, offset, IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_SIZE, IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_SIZE;
}

/* Reserved */
#define IEXEQUITIES_TOPSSNAP_RESERVED_NAME        "Reserved"
#define IEXEQUITIES_TOPSSNAP_RESERVED_DESCRIPTION "Reserved byte"
#define IEXEQUITIES_TOPSSNAP_RESERVED_FILTER      "iexequities.topssnap.reserved"
#define IEXEQUITIES_TOPSSNAP_RESERVED_TYPE        FT_BYTES
#define IEXEQUITIES_TOPSSNAP_RESERVED_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPSSNAP_RESERVED_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_RESERVED_ENCODING    ENC_NA
#define IEXEQUITIES_TOPSSNAP_RESERVED_SIZE        1

static unsigned
parse_iexequities_topssnap_reserved(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_reserved, tvb, offset, IEXEQUITIES_TOPSSNAP_RESERVED_SIZE, IEXEQUITIES_TOPSSNAP_RESERVED_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_RESERVED_SIZE;
}

/* Retail Liquidity Indicator */
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_NAME        "Retail Liquidity Indicator"
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION "Retail Liquidity Indicator identifier"
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_FILTER      "iexequities.topssnap.retailliquidityindicator"
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE        1

static const value_string iexequities_topssnap_retail_liquidity_indicator_vals[] = {
    { ' ', "Not Applicable" },
    { 'A', "Buy Interest" },
    { 'B', "Sell Interest" },
    { 'C', "Buy And Sell Interest" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_retail_liquidity_indicator, tvb, offset, IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE, IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_SIZE;
}

/* Round Lot Size */
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_NAME        "Round Lot Size"
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_DESCRIPTION "Number of shares that represent a round lot"
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_FILTER      "iexequities.topssnap.roundlotsize"
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_SIZE        4

static unsigned
parse_iexequities_topssnap_round_lot_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_round_lot_size, tvb, offset, IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_SIZE, IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_SIZE;
}

/* Scheduled Auction Time */
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_NAME        "Scheduled Auction Time"
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_DESCRIPTION "Projected time of the auction match"
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_FILTER      "iexequities.topssnap.scheduledauctiontime"
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_ENCODING    ENC_TIME_SECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_SIZE        4

static unsigned
parse_iexequities_topssnap_scheduled_auction_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_scheduled_auction_time, tvb, offset, IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_SIZE, IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_SIZE;
}

/* Send Time */
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_NAME        "Send Time"
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_DESCRIPTION "Send time of segment"
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_FILTER      "iexequities.topssnap.sendtime"
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SEND_TIME_SIZE        8

static unsigned
parse_iexequities_topssnap_send_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_send_time, tvb, offset, IEXEQUITIES_TOPSSNAP_SEND_TIME_SIZE, IEXEQUITIES_TOPSSNAP_SEND_TIME_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SEND_TIME_SIZE;
}

/* Session Id */
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_NAME        "Session Id"
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_DESCRIPTION "Session identifier from the Tops feed IexTp header"
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_FILTER      "iexequities.topssnap.sessionid"
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SESSION_ID_SIZE        4

static unsigned
parse_iexequities_topssnap_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_session_id, tvb, offset, IEXEQUITIES_TOPSSNAP_SESSION_ID_SIZE, IEXEQUITIES_TOPSSNAP_SESSION_ID_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SESSION_ID_SIZE;
}

/* Short Sale Price Test Status */
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_NAME        "Short Sale Price Test Status"
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION "Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_FILTER      "iexequities.topssnap.shortsalepriceteststatus"
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_TYPE        FT_UINT8
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE        1

static const value_string iexequities_topssnap_short_sale_price_test_status_vals[] = {
    { 0, "Not In Effect" },
    { 1, "In Effect" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_short_sale_price_test_status, tvb, offset, IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE, IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_SIZE;
}

/* Singleprice Cross Trade */
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_NAME        "Singleprice Cross Trade"
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_DESCRIPTION "Trade resulting from a single-price cross"
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_FILTER      "iexequities.topssnap.singlepricecrosstrade"
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_MASK        0x08

/* Size */
#define IEXEQUITIES_TOPSSNAP_SIZE_NAME        "Size"
#define IEXEQUITIES_TOPSSNAP_SIZE_DESCRIPTION "Trade volume"
#define IEXEQUITIES_TOPSSNAP_SIZE_FILTER      "iexequities.topssnap.size"
#define IEXEQUITIES_TOPSSNAP_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPSSNAP_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_SIZE_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SIZE_SIZE        4

static unsigned
parse_iexequities_topssnap_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_size, tvb, offset, IEXEQUITIES_TOPSSNAP_SIZE_SIZE, IEXEQUITIES_TOPSSNAP_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SIZE_SIZE;
}

/* Snapshot Length */
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_NAME        "Snapshot Length"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_DESCRIPTION "Length in bytes of the complete Snapshot Response including the Snapshot Start message, all Snapshot Data messages, and the Snapshot End message"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_FILTER      "iexequities.topssnap.snapshotlength"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_SIZE        8

static unsigned
parse_iexequities_topssnap_snapshot_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_snapshot_length, tvb, offset, IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_SIZE, IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_SIZE;
}

/* Snapshot Sequence Number */
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_NAME        "Snapshot Sequence Number"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DESCRIPTION "Sequence at which the snapshot was created"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_FILTER      "iexequities.topssnap.snapshotsequencenumber"
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_topssnap_snapshot_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_snapshot_sequence_number, tvb, offset, IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_SIZE;
}

/* Stream Offset */
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_NAME        "Stream Offset"
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_DESCRIPTION "Byte offset of the data stream"
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_FILTER      "iexequities.topssnap.streamoffset"
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_SIZE        8

static unsigned
parse_iexequities_topssnap_stream_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_stream_offset, tvb, offset, IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_SIZE, IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_SIZE;
}

/* Symbol */
#define IEXEQUITIES_TOPSSNAP_SYMBOL_NAME        "Symbol"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_DESCRIPTION "Security identifier"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_FILTER      "iexequities.topssnap.symbol"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_TYPE        FT_STRING
#define IEXEQUITIES_TOPSSNAP_SYMBOL_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPSSNAP_SYMBOL_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SYMBOL_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_SYMBOL_SIZE        8

static unsigned
parse_iexequities_topssnap_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_symbol, tvb, offset, IEXEQUITIES_TOPSSNAP_SYMBOL_SIZE, IEXEQUITIES_TOPSSNAP_SYMBOL_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SYMBOL_SIZE;
}

/* Symbol Availability */
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_NAME        "Symbol Availability"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_DESCRIPTION "Symbol is halted, paused, or otherwise not available for trading on IEX"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_FILTER      "iexequities.topssnap.symbolavailability"
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_MASK        0x80

/* System Event */
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_NAME        "System Event"
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_DESCRIPTION "System event identifier"
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_FILTER      "iexequities.topssnap.systemevent"
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_SIZE        1

static const value_string iexequities_topssnap_system_event_vals[] = {
    { 'O', "Start Of Messages" },
    { 'S', "Start Of System Hours" },
    { 'R', "Start Of Regular Market Hours" },
    { 'M', "End Of Regular Market Hours" },
    { 'E', "End Of System Hours" },
    { 'C', "End Of Messages" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_system_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_system_event, tvb, offset, IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_SIZE, IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_SIZE;
}

/* Test Security */
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_NAME        "Test Security"
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_DESCRIPTION "Symbol is a test security"
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_FILTER      "iexequities.topssnap.testsecurity"
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_TEST_SECURITY_MASK        0x80

/* Timestamp */
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_NAME        "Timestamp"
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_DESCRIPTION "Time stamp of the system event"
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_FILTER      "iexequities.topssnap.timestamp"
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_TIMESTAMP_SIZE        8

static unsigned
parse_iexequities_topssnap_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_timestamp, tvb, offset, IEXEQUITIES_TOPSSNAP_TIMESTAMP_SIZE, IEXEQUITIES_TOPSSNAP_TIMESTAMP_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_TIMESTAMP_SIZE;
}

/* Trade Id */
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_NAME        "Trade Id"
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_DESCRIPTION "IEX Generated Identifier"
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_FILTER      "iexequities.topssnap.tradeid"
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_TYPE        FT_UINT64
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_TRADE_ID_SIZE        8

static unsigned
parse_iexequities_topssnap_trade_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_trade_id, tvb, offset, IEXEQUITIES_TOPSSNAP_TRADE_ID_SIZE, IEXEQUITIES_TOPSSNAP_TRADE_ID_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_TRADE_ID_SIZE;
}

/* Trade Through Exempt */
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_NAME        "Trade Through Exempt"
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_DESCRIPTION "Trade is not subject to Rule 611"
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_FILTER      "iexequities.topssnap.tradethroughexempt"
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_MASK        0x10

/* Trading Status */
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_NAME        "Trading Status"
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_DESCRIPTION "Trading status identifier"
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_FILTER      "iexequities.topssnap.tradingstatus"
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPSSNAP_TRADING_STATUS_SIZE        1

static const value_string iexequities_topssnap_trading_status_vals[] = {
    { 'H', "Trading Halted Across All Us Equity Markets" },
    { 'O', "Trading Halt Released Into An Order Acceptance Period On Iex" },
    { 'P', "Trading Paused And Order Acceptance Period On Iex" },
    { 'T', "Trading On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_topssnap_trading_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_trading_status, tvb, offset, IEXEQUITIES_TOPSSNAP_TRADING_STATUS_SIZE, IEXEQUITIES_TOPSSNAP_TRADING_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_TRADING_STATUS_SIZE;
}

/* Upper Auction Collar */
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_NAME        "Upper Auction Collar"
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_DESCRIPTION "Upper threshold price of the auction collar, if any"
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_FILTER      "iexequities.topssnap.upperauctioncollar"
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_TYPE        FT_INT64
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_SIZE        8

static unsigned
parse_iexequities_topssnap_upper_auction_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_upper_auction_collar, tvb, offset, IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_SIZE, IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_SIZE;
}

/* Version */
#define IEXEQUITIES_TOPSSNAP_VERSION_NAME        "Version"
#define IEXEQUITIES_TOPSSNAP_VERSION_DESCRIPTION "Version of transport specification"
#define IEXEQUITIES_TOPSSNAP_VERSION_FILTER      "iexequities.topssnap.version"
#define IEXEQUITIES_TOPSSNAP_VERSION_TYPE        FT_UINT8
#define IEXEQUITIES_TOPSSNAP_VERSION_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPSSNAP_VERSION_MASK        0x0
#define IEXEQUITIES_TOPSSNAP_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_VERSION_SIZE        1

static unsigned
parse_iexequities_topssnap_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_topssnap_version, tvb, offset, IEXEQUITIES_TOPSSNAP_VERSION_SIZE, IEXEQUITIES_TOPSSNAP_VERSION_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_VERSION_SIZE;
}

/* When Issued */
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_NAME        "When Issued"
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_DESCRIPTION "Symbol is a when issued security"
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_FILTER      "iexequities.topssnap.whenissued"
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_DISPLAY     8
#define IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_MASK        0x40

/*
 * IexEquities Tops Structs
 */

/* Security Directory Flags */
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_NAME     "Security Directory Flags"
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_FILTER   "iexequities.topssnap.securitydirectoryflags"
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_MASK     0x0
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_SIZE     1

static int * const iexequities_topssnap_security_directory_flags_fields[] = {
    &hf_iexequities_topssnap_test_security,
    &hf_iexequities_topssnap_when_issued,
    &hf_iexequities_topssnap_etp,
    NULL
};

static unsigned
parse_iexequities_topssnap_security_directory_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_topssnap_security_directory_flags,
        ett_iexequities_topssnap_security_directory_flags, iexequities_topssnap_security_directory_flags_fields, IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_SIZE;
}

/* Quote Update Flags */
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_NAME     "Quote Update Flags"
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_FILTER   "iexequities.topssnap.quoteupdateflags"
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_MASK     0x0
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_SIZE     1

static int * const iexequities_topssnap_quote_update_flags_fields[] = {
    &hf_iexequities_topssnap_symbol_availability,
    &hf_iexequities_topssnap_market_session,
    NULL
};

static unsigned
parse_iexequities_topssnap_quote_update_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_topssnap_quote_update_flags,
        ett_iexequities_topssnap_quote_update_flags, iexequities_topssnap_quote_update_flags_fields, IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_SIZE;
}

/* Sale Condition Flags */
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_NAME     "Sale Condition Flags"
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_FILTER   "iexequities.topssnap.saleconditionflags"
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_TYPE     FT_UINT8
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_DISPLAY  BASE_HEX
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_MASK     0x0
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_ENCODING ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_SIZE     1

static int * const iexequities_topssnap_sale_condition_flags_fields[] = {
    &hf_iexequities_topssnap_intermarket_sweep,
    &hf_iexequities_topssnap_extended_hours,
    &hf_iexequities_topssnap_odd_lot,
    &hf_iexequities_topssnap_trade_through_exempt,
    &hf_iexequities_topssnap_singleprice_cross_trade,
    NULL
};

static unsigned
parse_iexequities_topssnap_sale_condition_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_topssnap_sale_condition_flags,
        ett_iexequities_topssnap_sale_condition_flags, iexequities_topssnap_sale_condition_flags_fields, IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_iexequities_topssnap_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_snapshot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_error_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_snapshot_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_snapshot_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_iextp_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_snapshot_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_quote_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_trade_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_official_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_auction_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_topssnap_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_iexequities_topssnap_iex_tp_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t iex_tp_message_type);

/* Message Header */
static unsigned
dissect_iexequities_topssnap_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (iexequities_topssnap_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_iexequities_topssnap_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_iexequities_topssnap_message_length(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Snapshot Request Message */
static unsigned
dissect_iexequities_topssnap_snapshot_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_authentication_token(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_channel_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_session_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_minimum_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Error Response Message */
static unsigned
dissect_iexequities_topssnap_error_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_reject_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Start Message */
static unsigned
dissect_iexequities_topssnap_snapshot_start(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_snapshot_length(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Data Message */
static unsigned
dissect_iexequities_topssnap_snapshot_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_iexequities_topssnap_iextp_header(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_iex_tp_message_block_length(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_iex_tp_message_length(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_iex_tp_message_type(tvb, pinfo, tree, offset);

    uint32_t iex_tp_message_type = tvb_get_uint8(tvb, start + 44);

    offset = dissect_iexequities_topssnap_iex_tp_message_data(tvb, pinfo, tree, offset, iex_tp_message_type);

    return offset;
}

/* Iextp Header */
static unsigned
dissect_iexequities_topssnap_iextp_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (iexequities_topssnap_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_iexequities_topssnap_iextp_header, &item, "Iextp Header");
    }

    unsigned start = offset;

    offset = parse_iexequities_topssnap_version(tvb, pinfo, group, offset);
    offset += IEXEQUITIES_TOPSSNAP_RESERVED_SIZE;
    offset = parse_iexequities_topssnap_message_protocol_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_channel_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_session_id(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_payload_length(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_message_count(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_stream_offset(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_first_message_sequence_number(tvb, pinfo, group, offset);
    offset = parse_iexequities_topssnap_send_time(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Snapshot End Message */
static unsigned
dissect_iexequities_topssnap_snapshot_end(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_snapshot_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message */
static unsigned
dissect_iexequities_topssnap_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_system_event(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);

    return offset;
}

/* Security Directory Message */
static unsigned
dissect_iexequities_topssnap_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_security_directory_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_adjusted_poc_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_luld_tier(tvb, pinfo, tree, offset);

    return offset;
}

/* Trading Status Message */
static unsigned
dissect_iexequities_topssnap_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_trading_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Liquidity Indicator Message */
static unsigned
dissect_iexequities_topssnap_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Operational Halt Status Message */
static unsigned
dissect_iexequities_topssnap_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_operational_halt_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Short Sale Price Test Status Message */
static unsigned
dissect_iexequities_topssnap_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_short_sale_price_test_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_detail(tvb, pinfo, tree, offset);

    return offset;
}

/* Quote Update Message */
static unsigned
dissect_iexequities_topssnap_quote_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_quote_update_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_bid_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_bid_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_ask_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_ask_size(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Report Message */
static unsigned
dissect_iexequities_topssnap_trade_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Official Price Message */
static unsigned
dissect_iexequities_topssnap_official_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_price_type(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_official_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Break Message */
static unsigned
dissect_iexequities_topssnap_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Auction Information Message */
static unsigned
dissect_iexequities_topssnap_auction_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_topssnap_auction_type(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_reference_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_indicative_clearing_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_imbalance_side(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_extension_number(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_scheduled_auction_time(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_auction_book_clearing_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_collar_reference_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_lower_auction_collar(tvb, pinfo, tree, offset);
    offset = parse_iexequities_topssnap_upper_auction_collar(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * IexEquities Tops Parse Trees, a dispatch per distinct branch definition
 */

static const value_string iexequities_topssnap_messages[] = {
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST, "Snapshot Request Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ERROR_RESPONSE, "Error Response Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_START, "Snapshot Start Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA, "Snapshot Data Message" },
    { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_END, "Snapshot End Message" },
    { 0, NULL }
};

/* Message Data: dispatch on message_type */
static unsigned
dissect_iexequities_topssnap_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, iexequities_topssnap_messages, "Unknown (%u)"));

    switch (message_type) {
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST:
        return dissect_iexequities_topssnap_snapshot_request(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ERROR_RESPONSE:
        return dissect_iexequities_topssnap_error_response(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_START:
        return dissect_iexequities_topssnap_snapshot_start(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA:
        return dissect_iexequities_topssnap_snapshot_data(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_END:
        return dissect_iexequities_topssnap_snapshot_end(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string iexequities_topssnap_iex_tp_message_data_messages[] = {
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OFFICIAL_PRICE, "Official Price Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_AUCTION_INFORMATION, "Auction Information Message" },
    { 0, NULL }
};

/* Iex Tp Message Data: dispatch on iex_tp_message_type */
static unsigned
dissect_iexequities_topssnap_iex_tp_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t iex_tp_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, iex_tp_message_type, iexequities_topssnap_iex_tp_message_data_messages, "Unknown (%u)"));

    switch (iex_tp_message_type) {
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_iexequities_topssnap_system_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SECURITY_DIRECTORY:
        return dissect_iexequities_topssnap_security_directory(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADING_STATUS:
        return dissect_iexequities_topssnap_trading_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR:
        return dissect_iexequities_topssnap_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS:
        return dissect_iexequities_topssnap_operational_halt_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS:
        return dissect_iexequities_topssnap_short_sale_price_test_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_QUOTE_UPDATE:
        return dissect_iexequities_topssnap_quote_update(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_REPORT:
        return dissect_iexequities_topssnap_trade_report(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_OFFICIAL_PRICE:
        return dissect_iexequities_topssnap_official_price(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TRADE_BREAK:
        return dissect_iexequities_topssnap_trade_break(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_AUCTION_INFORMATION:
        return dissect_iexequities_topssnap_auction_information(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
iexequities_topssnap_show(uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_REQUEST:
        return iexequities_topssnap_show_application_messages;
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_ERROR_RESPONSE:
        return iexequities_topssnap_show_application_messages;
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_START:
        return iexequities_topssnap_show_application_messages;
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_DATA:
        return iexequities_topssnap_show_application_messages;
    case IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_SNAPSHOT_END:
        return iexequities_topssnap_show_application_messages;
    }

    return true;
}

typedef struct iexequities_topssnap_parse iexequities_topssnap_parse;

struct iexequities_topssnap_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
};

static const iexequities_topssnap_parse iexequities_topssnap_parse_v16 = { iexequities_topssnap_messages, dissect_iexequities_topssnap_message_data };

/* Parse tree of the selected version */
static const iexequities_topssnap_parse *
iexequities_topssnap_parse_for(int version)
{
    switch (version) {
    default:
        return &iexequities_topssnap_parse_v16;
    }
}

/* IexEquities Tops message size adjusts the declared length */
#define IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_iexequities_topssnap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const iexequities_topssnap_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = iexequities_topssnap_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length + IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT, ett_iexequities_topssnap_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_iexequities_topssnap_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length + IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_iexequities_topssnap_length);
    }

    return message_length + IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_iexequities_topssnap_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const iexequities_topssnap_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_letohs(tvb, offset) + IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_iexequities_topssnap_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_iexequities_topssnap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, IEXEQUITIES_TOPSSNAP_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_iexequities_topssnap, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_iexequities_topssnap);

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = iexequities_topssnap_version(seconds);

    proto_item_append_text(item, " %s", iexequities_topssnap_version_name(version));

    const iexequities_topssnap_parse *parse = iexequities_topssnap_parse_for(version);
    unsigned position = 0;

    position = dissect_iexequities_topssnap_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define IEXEQUITIES_TOPSSNAP_MINIMUM_SIZE 3

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
iexequities_topssnap_heur_port(packet_info *pinfo)
{
    return value_is_in_range(iexequities_topssnap_pref_ports, pinfo->destport)
        || value_is_in_range(iexequities_topssnap_pref_ports, pinfo->srcport);
}

/* The first frame's declared length fits the stream */
static bool
iexequities_topssnap_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_letohs(tvb, 0) + IEXEQUITIES_TOPSSNAP_MESSAGE_ADJUSTMENT);

    return frame >= IEXEQUITIES_TOPSSNAP_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Does the frame pass every test of Packet? */
static bool
iexequities_topssnap_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!iexequities_topssnap_heur_port(pinfo)) {
        return false;
    }

    if (!iexequities_topssnap_heur_frame(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on */
static bool
dissect_iexequities_topssnap_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < IEXEQUITIES_TOPSSNAP_MINIMUM_SIZE) {
        return false;
    }

    if (!iexequities_topssnap_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_iexequities_topssnap(tvb, pinfo, tree, data);

    return true;
}

/*
 * IexEquities Tops Registration
 */

void
proto_register_iexequities_topssnap(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_iexequities_topssnap_adjusted_poc_price,
            { IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_ADJUSTED_POC_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_ask_price,
            { IEXEQUITIES_TOPSSNAP_ASK_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_ASK_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_ASK_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_ASK_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_ASK_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_ASK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_ask_size,
            { IEXEQUITIES_TOPSSNAP_ASK_SIZE_NAME,
              IEXEQUITIES_TOPSSNAP_ASK_SIZE_FILTER,
              IEXEQUITIES_TOPSSNAP_ASK_SIZE_TYPE,
              IEXEQUITIES_TOPSSNAP_ASK_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_ASK_SIZE_MASK,
              IEXEQUITIES_TOPSSNAP_ASK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_auction_book_clearing_price,
            { IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_AUCTION_BOOK_CLEARING_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_auction_type,
            { IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_NAME,
              IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_FILTER,
              IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_TYPE,
              IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_DISPLAY,
              VALS(iexequities_topssnap_auction_type_vals),
              IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_MASK,
              IEXEQUITIES_TOPSSNAP_AUCTION_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_authentication_token,
            { IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_NAME,
              IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_FILTER,
              IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_TYPE,
              IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_MASK,
              IEXEQUITIES_TOPSSNAP_AUTHENTICATION_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_bid_price,
            { IEXEQUITIES_TOPSSNAP_BID_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_BID_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_BID_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_BID_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_BID_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_BID_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_bid_size,
            { IEXEQUITIES_TOPSSNAP_BID_SIZE_NAME,
              IEXEQUITIES_TOPSSNAP_BID_SIZE_FILTER,
              IEXEQUITIES_TOPSSNAP_BID_SIZE_TYPE,
              IEXEQUITIES_TOPSSNAP_BID_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_BID_SIZE_MASK,
              IEXEQUITIES_TOPSSNAP_BID_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_channel_id,
            { IEXEQUITIES_TOPSSNAP_CHANNEL_ID_NAME,
              IEXEQUITIES_TOPSSNAP_CHANNEL_ID_FILTER,
              IEXEQUITIES_TOPSSNAP_CHANNEL_ID_TYPE,
              IEXEQUITIES_TOPSSNAP_CHANNEL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_CHANNEL_ID_MASK,
              IEXEQUITIES_TOPSSNAP_CHANNEL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_collar_reference_price,
            { IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_COLLAR_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_detail,
            { IEXEQUITIES_TOPSSNAP_DETAIL_NAME,
              IEXEQUITIES_TOPSSNAP_DETAIL_FILTER,
              IEXEQUITIES_TOPSSNAP_DETAIL_TYPE,
              IEXEQUITIES_TOPSSNAP_DETAIL_DISPLAY,
              VALS(iexequities_topssnap_detail_vals),
              IEXEQUITIES_TOPSSNAP_DETAIL_MASK,
              IEXEQUITIES_TOPSSNAP_DETAIL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_extension_number,
            { IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_NAME,
              IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_FILTER,
              IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_TYPE,
              IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_MASK,
              IEXEQUITIES_TOPSSNAP_EXTENSION_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_first_message_sequence_number,
            { IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_TOPSSNAP_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_iex_tp_message_block_length,
            { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_NAME,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_FILTER,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_TYPE,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_MASK,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_iex_tp_message_length,
            { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_NAME,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_FILTER,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_TYPE,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_MASK,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_iex_tp_message_type,
            { IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_NAME,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_FILTER,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_TYPE,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_DISPLAY,
              VALS(iexequities_topssnap_iex_tp_message_type_vals),
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_MASK,
              IEXEQUITIES_TOPSSNAP_IEX_TP_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_imbalance_shares,
            { IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_NAME,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_FILTER,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_TYPE,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_MASK,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_imbalance_side,
            { IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_NAME,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_FILTER,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_TYPE,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_DISPLAY,
              VALS(iexequities_topssnap_imbalance_side_vals),
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_MASK,
              IEXEQUITIES_TOPSSNAP_IMBALANCE_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_indicative_clearing_price,
            { IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_INDICATIVE_CLEARING_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_lower_auction_collar,
            { IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_NAME,
              IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_FILTER,
              IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_TYPE,
              IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_MASK,
              IEXEQUITIES_TOPSSNAP_LOWER_AUCTION_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_luld_tier,
            { IEXEQUITIES_TOPSSNAP_LULD_TIER_NAME,
              IEXEQUITIES_TOPSSNAP_LULD_TIER_FILTER,
              IEXEQUITIES_TOPSSNAP_LULD_TIER_TYPE,
              IEXEQUITIES_TOPSSNAP_LULD_TIER_DISPLAY,
              VALS(iexequities_topssnap_luld_tier_vals),
              IEXEQUITIES_TOPSSNAP_LULD_TIER_MASK,
              IEXEQUITIES_TOPSSNAP_LULD_TIER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_message_count,
            { IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_NAME,
              IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_FILTER,
              IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_TYPE,
              IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_MASK,
              IEXEQUITIES_TOPSSNAP_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_message_length,
            { IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_NAME,
              IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_FILTER,
              IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_TYPE,
              IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_MASK,
              IEXEQUITIES_TOPSSNAP_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_message_protocol_id,
            { IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_NAME,
              IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_FILTER,
              IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_TYPE,
              IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_MASK,
              IEXEQUITIES_TOPSSNAP_MESSAGE_PROTOCOL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_message_type,
            { IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_NAME,
              IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_FILTER,
              IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_TYPE,
              IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_DISPLAY,
              VALS(iexequities_topssnap_message_type_vals),
              IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_MASK,
              IEXEQUITIES_TOPSSNAP_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_minimum_sequence_number,
            { IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_TOPSSNAP_MINIMUM_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_official_price,
            { IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_OFFICIAL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_operational_halt_status,
            { IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_NAME,
              IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_FILTER,
              IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_TYPE,
              IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_DISPLAY,
              VALS(iexequities_topssnap_operational_halt_status_vals),
              IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_MASK,
              IEXEQUITIES_TOPSSNAP_OPERATIONAL_HALT_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_paired_shares,
            { IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_NAME,
              IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_FILTER,
              IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_TYPE,
              IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_MASK,
              IEXEQUITIES_TOPSSNAP_PAIRED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_payload_length,
            { IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_NAME,
              IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_FILTER,
              IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_TYPE,
              IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_MASK,
              IEXEQUITIES_TOPSSNAP_PAYLOAD_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_price,
            { IEXEQUITIES_TOPSSNAP_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_price_type,
            { IEXEQUITIES_TOPSSNAP_PRICE_TYPE_NAME,
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE_FILTER,
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE_TYPE,
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE_DISPLAY,
              VALS(iexequities_topssnap_price_type_vals),
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE_MASK,
              IEXEQUITIES_TOPSSNAP_PRICE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_reason,
            { IEXEQUITIES_TOPSSNAP_REASON_NAME,
              IEXEQUITIES_TOPSSNAP_REASON_FILTER,
              IEXEQUITIES_TOPSSNAP_REASON_TYPE,
              IEXEQUITIES_TOPSSNAP_REASON_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_REASON_MASK,
              IEXEQUITIES_TOPSSNAP_REASON_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_reference_price,
            { IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_NAME,
              IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_FILTER,
              IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_TYPE,
              IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_MASK,
              IEXEQUITIES_TOPSSNAP_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_reject_reason_code,
            { IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_NAME,
              IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_FILTER,
              IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_TYPE,
              IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_DISPLAY,
              VALS(iexequities_topssnap_reject_reason_code_vals),
              IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_MASK,
              IEXEQUITIES_TOPSSNAP_REJECT_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_reserved,
            { IEXEQUITIES_TOPSSNAP_RESERVED_NAME,
              IEXEQUITIES_TOPSSNAP_RESERVED_FILTER,
              IEXEQUITIES_TOPSSNAP_RESERVED_TYPE,
              IEXEQUITIES_TOPSSNAP_RESERVED_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_RESERVED_MASK,
              IEXEQUITIES_TOPSSNAP_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_retail_liquidity_indicator,
            { IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_NAME,
              IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_FILTER,
              IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_TYPE,
              IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_DISPLAY,
              VALS(iexequities_topssnap_retail_liquidity_indicator_vals),
              IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_MASK,
              IEXEQUITIES_TOPSSNAP_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_round_lot_size,
            { IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_NAME,
              IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_FILTER,
              IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_TYPE,
              IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_MASK,
              IEXEQUITIES_TOPSSNAP_ROUND_LOT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_scheduled_auction_time,
            { IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_NAME,
              IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_FILTER,
              IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_TYPE,
              IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_MASK,
              IEXEQUITIES_TOPSSNAP_SCHEDULED_AUCTION_TIME_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_send_time,
            { IEXEQUITIES_TOPSSNAP_SEND_TIME_NAME,
              IEXEQUITIES_TOPSSNAP_SEND_TIME_FILTER,
              IEXEQUITIES_TOPSSNAP_SEND_TIME_TYPE,
              IEXEQUITIES_TOPSSNAP_SEND_TIME_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SEND_TIME_MASK,
              IEXEQUITIES_TOPSSNAP_SEND_TIME_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_session_id,
            { IEXEQUITIES_TOPSSNAP_SESSION_ID_NAME,
              IEXEQUITIES_TOPSSNAP_SESSION_ID_FILTER,
              IEXEQUITIES_TOPSSNAP_SESSION_ID_TYPE,
              IEXEQUITIES_TOPSSNAP_SESSION_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SESSION_ID_MASK,
              IEXEQUITIES_TOPSSNAP_SESSION_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_short_sale_price_test_status,
            { IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_NAME,
              IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_FILTER,
              IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_TYPE,
              IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY,
              VALS(iexequities_topssnap_short_sale_price_test_status_vals),
              IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_MASK,
              IEXEQUITIES_TOPSSNAP_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_size,
            { IEXEQUITIES_TOPSSNAP_SIZE_NAME,
              IEXEQUITIES_TOPSSNAP_SIZE_FILTER,
              IEXEQUITIES_TOPSSNAP_SIZE_TYPE,
              IEXEQUITIES_TOPSSNAP_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SIZE_MASK,
              IEXEQUITIES_TOPSSNAP_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_snapshot_length,
            { IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_NAME,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_FILTER,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_TYPE,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_MASK,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_snapshot_sequence_number,
            { IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_TOPSSNAP_SNAPSHOT_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_stream_offset,
            { IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_NAME,
              IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_FILTER,
              IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_TYPE,
              IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_MASK,
              IEXEQUITIES_TOPSSNAP_STREAM_OFFSET_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_symbol,
            { IEXEQUITIES_TOPSSNAP_SYMBOL_NAME,
              IEXEQUITIES_TOPSSNAP_SYMBOL_FILTER,
              IEXEQUITIES_TOPSSNAP_SYMBOL_TYPE,
              IEXEQUITIES_TOPSSNAP_SYMBOL_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SYMBOL_MASK,
              IEXEQUITIES_TOPSSNAP_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_system_event,
            { IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_NAME,
              IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_FILTER,
              IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_TYPE,
              IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_DISPLAY,
              VALS(iexequities_topssnap_system_event_vals),
              IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_MASK,
              IEXEQUITIES_TOPSSNAP_SYSTEM_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_timestamp,
            { IEXEQUITIES_TOPSSNAP_TIMESTAMP_NAME,
              IEXEQUITIES_TOPSSNAP_TIMESTAMP_FILTER,
              IEXEQUITIES_TOPSSNAP_TIMESTAMP_TYPE,
              IEXEQUITIES_TOPSSNAP_TIMESTAMP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_TIMESTAMP_MASK,
              IEXEQUITIES_TOPSSNAP_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_trade_id,
            { IEXEQUITIES_TOPSSNAP_TRADE_ID_NAME,
              IEXEQUITIES_TOPSSNAP_TRADE_ID_FILTER,
              IEXEQUITIES_TOPSSNAP_TRADE_ID_TYPE,
              IEXEQUITIES_TOPSSNAP_TRADE_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_TRADE_ID_MASK,
              IEXEQUITIES_TOPSSNAP_TRADE_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_trading_status,
            { IEXEQUITIES_TOPSSNAP_TRADING_STATUS_NAME,
              IEXEQUITIES_TOPSSNAP_TRADING_STATUS_FILTER,
              IEXEQUITIES_TOPSSNAP_TRADING_STATUS_TYPE,
              IEXEQUITIES_TOPSSNAP_TRADING_STATUS_DISPLAY,
              VALS(iexequities_topssnap_trading_status_vals),
              IEXEQUITIES_TOPSSNAP_TRADING_STATUS_MASK,
              IEXEQUITIES_TOPSSNAP_TRADING_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_upper_auction_collar,
            { IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_NAME,
              IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_FILTER,
              IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_TYPE,
              IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_DISPLAY,
              CF_FUNC(iexequities_topssnap_format_decimal_4_64),
              IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_MASK,
              IEXEQUITIES_TOPSSNAP_UPPER_AUCTION_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_version,
            { IEXEQUITIES_TOPSSNAP_VERSION_NAME,
              IEXEQUITIES_TOPSSNAP_VERSION_FILTER,
              IEXEQUITIES_TOPSSNAP_VERSION_TYPE,
              IEXEQUITIES_TOPSSNAP_VERSION_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_VERSION_MASK,
              IEXEQUITIES_TOPSSNAP_VERSION_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_iexequities_topssnap_etp,
            { IEXEQUITIES_TOPSSNAP_ETP_NAME,
              IEXEQUITIES_TOPSSNAP_ETP_FILTER,
              IEXEQUITIES_TOPSSNAP_ETP_TYPE,
              IEXEQUITIES_TOPSSNAP_ETP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_ETP_MASK,
              IEXEQUITIES_TOPSSNAP_ETP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_extended_hours,
            { IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_NAME,
              IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_FILTER,
              IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_TYPE,
              IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_MASK,
              IEXEQUITIES_TOPSSNAP_EXTENDED_HOURS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_intermarket_sweep,
            { IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_NAME,
              IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_FILTER,
              IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_TYPE,
              IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_MASK,
              IEXEQUITIES_TOPSSNAP_INTERMARKET_SWEEP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_market_session,
            { IEXEQUITIES_TOPSSNAP_MARKET_SESSION_NAME,
              IEXEQUITIES_TOPSSNAP_MARKET_SESSION_FILTER,
              IEXEQUITIES_TOPSSNAP_MARKET_SESSION_TYPE,
              IEXEQUITIES_TOPSSNAP_MARKET_SESSION_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_MARKET_SESSION_MASK,
              IEXEQUITIES_TOPSSNAP_MARKET_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_odd_lot,
            { IEXEQUITIES_TOPSSNAP_ODD_LOT_NAME,
              IEXEQUITIES_TOPSSNAP_ODD_LOT_FILTER,
              IEXEQUITIES_TOPSSNAP_ODD_LOT_TYPE,
              IEXEQUITIES_TOPSSNAP_ODD_LOT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_ODD_LOT_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_topssnap_singleprice_cross_trade,
            { IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_NAME,
              IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_FILTER,
              IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_TYPE,
              IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_MASK,
              IEXEQUITIES_TOPSSNAP_SINGLEPRICE_CROSS_TRADE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_symbol_availability,
            { IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_NAME,
              IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_FILTER,
              IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_TYPE,
              IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_MASK,
              IEXEQUITIES_TOPSSNAP_SYMBOL_AVAILABILITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_test_security,
            { IEXEQUITIES_TOPSSNAP_TEST_SECURITY_NAME,
              IEXEQUITIES_TOPSSNAP_TEST_SECURITY_FILTER,
              IEXEQUITIES_TOPSSNAP_TEST_SECURITY_TYPE,
              IEXEQUITIES_TOPSSNAP_TEST_SECURITY_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_TEST_SECURITY_MASK,
              IEXEQUITIES_TOPSSNAP_TEST_SECURITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_trade_through_exempt,
            { IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_NAME,
              IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_FILTER,
              IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_TYPE,
              IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_MASK,
              IEXEQUITIES_TOPSSNAP_TRADE_THROUGH_EXEMPT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_topssnap_when_issued,
            { IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_NAME,
              IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_FILTER,
              IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_TYPE,
              IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_MASK,
              IEXEQUITIES_TOPSSNAP_WHEN_ISSUED_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_iexequities_topssnap_security_directory_flags,
            { IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_NAME,
              IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_FILTER,
              IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_TYPE,
              IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SECURITY_DIRECTORY_FLAGS_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_topssnap_quote_update_flags,
            { IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_NAME,
              IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_FILTER,
              IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_TYPE,
              IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_QUOTE_UPDATE_FLAGS_MASK,
              NULL,
              HFILL } },
        { &hf_iexequities_topssnap_sale_condition_flags,
            { IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_NAME,
              IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_FILTER,
              IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_TYPE,
              IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPSSNAP_SALE_CONDITION_FLAGS_MASK,
              NULL,
              HFILL } },
    };

    static int *ett[] = {
        &ett_iexequities_topssnap,
        &ett_iexequities_topssnap_header,
        &ett_iexequities_topssnap_message,
        &ett_iexequities_topssnap_security_directory_flags,
        &ett_iexequities_topssnap_quote_update_flags,
        &ett_iexequities_topssnap_sale_condition_flags,
        &ett_iexequities_topssnap_message_header,
        &ett_iexequities_topssnap_iextp_header,
    };

    static ei_register_info ei[] = {
        { &ei_iexequities_topssnap_length,
            { IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_FILTER,
              IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_GROUP,
              IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_SEVERITY,
              IEXEQUITIES_TOPSSNAP_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_iexequities_topssnap = proto_register_protocol(IEXEQUITIES_TOPSSNAP_PROTOCOL_NAME, IEXEQUITIES_TOPSSNAP_PROTOCOL_SHORT, IEXEQUITIES_TOPSSNAP_PROTOCOL_FILTER);

    proto_register_field_array(proto_iexequities_topssnap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_iexequities_topssnap = expert_register_protocol(proto_iexequities_topssnap);
    expert_register_field_array(expert_iexequities_topssnap, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_iexequities_topssnap, NULL);

    prefs_register_enum_preference(
        preferences,
        IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_NAME,
        IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_TITLE,
        IEXEQUITIES_TOPSSNAP_VERSION_PREFERENCE_DESCRIPTION,
        &iexequities_topssnap_pref_version,
        iexequities_topssnap_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_NAME,
        IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_TITLE,
        IEXEQUITIES_TOPSSNAP_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &iexequities_topssnap_show_headers);

    prefs_register_bool_preference(
        preferences,
        IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        IEXEQUITIES_TOPSSNAP_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &iexequities_topssnap_show_application_messages);

    prefs_register_uint_preference(
        preferences,
        IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_NAME,
        IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_TITLE,
        IEXEQUITIES_TOPSSNAP_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &iexequities_topssnap_pref_decimal_places);

    range_convert_str(
        wmem_epan_scope(),
        &iexequities_topssnap_pref_ports,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_DEFAULT,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_NAME,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_TITLE,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_DESCRIPTION,
        &iexequities_topssnap_pref_ports,
        IEXEQUITIES_TOPSSNAP_PORTS_PREFERENCE_MAXIMUM);

    iexequities_topssnap_handle = register_dissector(IEXEQUITIES_TOPSSNAP_PROTOCOL_FILTER, dissect_iexequities_topssnap, proto_iexequities_topssnap);
}

void
proto_reg_handoff_iexequities_topssnap(void)
{
    heur_dissector_add("tcp", dissect_iexequities_topssnap_heur, "IEX TOPS SNAP over TCP",
        "iexequities_topssnap_tcp", proto_iexequities_topssnap, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", iexequities_topssnap_handle);
}
