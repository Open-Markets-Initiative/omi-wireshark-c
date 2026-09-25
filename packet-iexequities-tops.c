/* packet-iexequities-tops.c
 * Routines for IEX TOPS dissection
 *
 * Aggregated protocol versions: 1.66, 1.64, 1.56
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Iex.IexEquities.Tops.IexTp.v1.66
 *   Iex.IexEquities.Tops.IexTp.v1.64
 *   Iex.IexEquities.Tops.IexTp.v1.56
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

void proto_register_iexequities_tops(void);
void proto_reg_handoff_iexequities_tops(void);

static dissector_handle_t iexequities_tops_handle;

static int proto_iexequities_tops;

/*
 * IexEquities Tops Protocol
 */

#define IEXEQUITIES_TOPS_PROTOCOL_NAME "IEX TOPS"
#define IEXEQUITIES_TOPS_PROTOCOL_SHORT "IEXEQUITIES.TOPS"
#define IEXEQUITIES_TOPS_PROTOCOL_FILTER "iexequities.tops"

/*
 * IexEquities Tops Header
 */

#define IEXEQUITIES_TOPS_HEADER_SIZE 40 /* Iextp Header */

/*
 * IexEquities Tops Field Handles
 */

static int hf_iexequities_tops_adjusted_poc_price;
static int hf_iexequities_tops_ask_price;
static int hf_iexequities_tops_ask_size;
static int hf_iexequities_tops_auction_book_clearing_price;
static int hf_iexequities_tops_auction_type;
static int hf_iexequities_tops_bid_price;
static int hf_iexequities_tops_bid_size;
static int hf_iexequities_tops_channel_id;
static int hf_iexequities_tops_collar_reference_price;
static int hf_iexequities_tops_detail;
static int hf_iexequities_tops_etp;
static int hf_iexequities_tops_extended_hours;
static int hf_iexequities_tops_extension_number;
static int hf_iexequities_tops_first_message_sequence_number;
static int hf_iexequities_tops_imbalance_shares;
static int hf_iexequities_tops_imbalance_side;
static int hf_iexequities_tops_indicative_clearing_price;
static int hf_iexequities_tops_intermarket_sweep;
static int hf_iexequities_tops_lower_auction_collar;
static int hf_iexequities_tops_luld_tier;
static int hf_iexequities_tops_market_session;
static int hf_iexequities_tops_message_count;
static int hf_iexequities_tops_message_length;
static int hf_iexequities_tops_message_protocol_id;
static int hf_iexequities_tops_message_type;
static int hf_iexequities_tops_odd_lot;
static int hf_iexequities_tops_official_price;
static int hf_iexequities_tops_operational_halt_status;
static int hf_iexequities_tops_paired_shares;
static int hf_iexequities_tops_payload_length;
static int hf_iexequities_tops_price;
static int hf_iexequities_tops_price_type;
static int hf_iexequities_tops_quote_update_flags;
static int hf_iexequities_tops_reason;
static int hf_iexequities_tops_reference_price;
static int hf_iexequities_tops_reserved;
static int hf_iexequities_tops_reserved_4;
static int hf_iexequities_tops_retail_liquidity_indicator;
static int hf_iexequities_tops_round_lot_size;
static int hf_iexequities_tops_sale_condition_flags;
static int hf_iexequities_tops_sale_condition_flags_v156;
static int hf_iexequities_tops_scheduled_auction_time;
static int hf_iexequities_tops_security_directory_flags;
static int hf_iexequities_tops_security_event;
static int hf_iexequities_tops_send_time;
static int hf_iexequities_tops_session_id;
static int hf_iexequities_tops_short_sale_price_test_status;
static int hf_iexequities_tops_singleprice_cross_trade;
static int hf_iexequities_tops_size;
static int hf_iexequities_tops_stream_offset;
static int hf_iexequities_tops_symbol;
static int hf_iexequities_tops_symbol_availability;
static int hf_iexequities_tops_system_event;
static int hf_iexequities_tops_test_security;
static int hf_iexequities_tops_timestamp;
static int hf_iexequities_tops_trade_id;
static int hf_iexequities_tops_trade_through_exempt;
static int hf_iexequities_tops_trading_status;
static int hf_iexequities_tops_upper_auction_collar;
static int hf_iexequities_tops_version;
static int hf_iexequities_tops_when_issued;

/*
 * IexEquities Tops Subtrees
 */

static int ett_iexequities_tops;
static int ett_iexequities_tops_header;
static int ett_iexequities_tops_message;
static int ett_iexequities_tops_security_directory_flags;
static int ett_iexequities_tops_quote_update_flags;
static int ett_iexequities_tops_sale_condition_flags;
static int ett_iexequities_tops_sale_condition_flags_v156;
static int ett_iexequities_tops_message_header;

/*
 * IexEquities Tops Expert Information
 */

/* Message length does not account for the parsed fields */
#define IEXEQUITIES_TOPS_LENGTH_EXPERT_FILTER "iexequities.tops.length.invalid"
#define IEXEQUITIES_TOPS_LENGTH_EXPERT_GROUP PI_MALFORMED
#define IEXEQUITIES_TOPS_LENGTH_EXPERT_SEVERITY PI_ERROR
#define IEXEQUITIES_TOPS_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_iexequities_tops_length;

/*
 * IexEquities Tops Preferences
 */

#define IEXEQUITIES_TOPS_VERSION_PREFERENCE_NAME "version"
#define IEXEQUITIES_TOPS_VERSION_PREFERENCE_TITLE "Protocol version"
#define IEXEQUITIES_TOPS_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define IEXEQUITIES_TOPS_VERSION_AUTOMATIC 0
#define IEXEQUITIES_TOPS_VERSION_1_66     1
#define IEXEQUITIES_TOPS_VERSION_1_64     2
#define IEXEQUITIES_TOPS_VERSION_1_56     3

static const enum_val_t iexequities_tops_version_vals[] = {
    { "automatic", "Automatic (by send time)", IEXEQUITIES_TOPS_VERSION_AUTOMATIC },
    { "v1.66", "1.66", IEXEQUITIES_TOPS_VERSION_1_66 },
    { "v1.64", "1.64", IEXEQUITIES_TOPS_VERSION_1_64 },
    { "v1.56", "1.56", IEXEQUITIES_TOPS_VERSION_1_56 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
iexequities_tops_version_name(int version)
{
    switch (version) {
    case IEXEQUITIES_TOPS_VERSION_1_66:
        return "1.66";
    case IEXEQUITIES_TOPS_VERSION_1_64:
        return "1.64";
    case IEXEQUITIES_TOPS_VERSION_1_56:
        return "1.56";
    }

    return "";
}

static int iexequities_tops_pref_version = IEXEQUITIES_TOPS_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define IEXEQUITIES_TOPS_EFFECTIVE_1_66 UINT64_C(1633910400) /* 2021-10-11 */
#define IEXEQUITIES_TOPS_EFFECTIVE_1_64 UINT64_C(1588550400) /* 2020-05-04 */

/* Testing effective times, where a version went live apart from production */
#define IEXEQUITIES_TOPS_TESTING_EFFECTIVE_1_66 UINT64_C(1626652800) /* 2021-07-19 */

/* Environments the feed is published in, the destination endpoint names a frame's */
#define IEXEQUITIES_TOPS_ENVIRONMENT_AUTOMATIC 0
#define IEXEQUITIES_TOPS_ENVIRONMENT_PRODUCTION 1
#define IEXEQUITIES_TOPS_ENVIRONMENT_DISASTER_RECOVERY 2
#define IEXEQUITIES_TOPS_ENVIRONMENT_TESTING 3

#define IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_NAME "environment"
#define IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_TITLE "Environment"
#define IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_DESCRIPTION "Environment the capture was taken in, Automatic resolves it from the destination endpoint"

static const enum_val_t iexequities_tops_environment_vals[] = {
    { "automatic", "Automatic (by destination)", IEXEQUITIES_TOPS_ENVIRONMENT_AUTOMATIC },
    { "production", "Production", IEXEQUITIES_TOPS_ENVIRONMENT_PRODUCTION },
    { "disasterrecovery", "Disaster Recovery", IEXEQUITIES_TOPS_ENVIRONMENT_DISASTER_RECOVERY },
    { "testing", "Testing", IEXEQUITIES_TOPS_ENVIRONMENT_TESTING },
    { NULL, NULL, 0 }
};

static int iexequities_tops_pref_environment = IEXEQUITIES_TOPS_ENVIRONMENT_AUTOMATIC;

/* Show preferences, one per message and struct */
#define IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

static bool iexequities_tops_show_headers = true;
static bool iexequities_tops_show_application_messages = true;

/* Decimal places shown, the wire precision by default */
#define IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_NAME "decimal.places"
#define IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned iexequities_tops_pref_decimal_places = 4;

/* Entries of a repeating group are numbered */
#define IEXEQUITIES_TOPS_INDEXES_PREFERENCE_NAME "show.indexes"
#define IEXEQUITIES_TOPS_INDEXES_PREFERENCE_TITLE "Show Indexes"
#define IEXEQUITIES_TOPS_INDEXES_PREFERENCE_DESCRIPTION "Number the entries of a repeating group in the protocol tree"

static bool iexequities_tops_pref_show_indexes = true;

/*
 * IexEquities Tops Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch against the environment's dates */
static int
iexequities_tops_version(uint64_t seconds, int environment)
{
    if (iexequities_tops_pref_version != IEXEQUITIES_TOPS_VERSION_AUTOMATIC) {
        return iexequities_tops_pref_version;
    }

    if (environment == IEXEQUITIES_TOPS_ENVIRONMENT_TESTING) {
        if (seconds >= IEXEQUITIES_TOPS_TESTING_EFFECTIVE_1_66) {
            return IEXEQUITIES_TOPS_VERSION_1_66;
        }

        if (seconds >= IEXEQUITIES_TOPS_EFFECTIVE_1_64) {
            return IEXEQUITIES_TOPS_VERSION_1_64;
        }

        return IEXEQUITIES_TOPS_VERSION_1_56;
    }

    if (seconds >= IEXEQUITIES_TOPS_EFFECTIVE_1_66) {
        return IEXEQUITIES_TOPS_VERSION_1_66;
    }

    if (seconds >= IEXEQUITIES_TOPS_EFFECTIVE_1_64) {
        return IEXEQUITIES_TOPS_VERSION_1_64;
    }

    return IEXEQUITIES_TOPS_VERSION_1_56;
}

/* Cap the fraction at the preferred decimal places */
static void
iexequities_tops_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = iexequities_tops_pref_decimal_places;

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
iexequities_tops_format_decimal_4_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t whole = value / 10000;
    int64_t fraction = value % 10000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && whole == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%04" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%04" PRId64, whole, fraction);
    }

    iexequities_tops_decimal_places(buf);
}

/* Broadcast endpoints from the connectivity model */
typedef struct iexequities_tops_endpoint {
    uint8_t address[4];
    uint16_t port;
    int environment;
    const char *name;
} iexequities_tops_endpoint;

static const iexequities_tops_endpoint iexequities_tops_endpoints[] = {
    { { 233, 215, 21, 3 }, 10377, IEXEQUITIES_TOPS_ENVIRONMENT_PRODUCTION, "Feed A Equinix NY5" },
    { { 233, 215, 21, 131 }, 10377, IEXEQUITIES_TOPS_ENVIRONMENT_PRODUCTION, "Feed B Equinix NY5" },
    { { 233, 215, 21, 67 }, 10377, IEXEQUITIES_TOPS_ENVIRONMENT_DISASTER_RECOVERY, "Feed C Equinix CH4, Disaster Recovery" },
    { { 233, 215, 21, 240 }, 32002, IEXEQUITIES_TOPS_ENVIRONMENT_TESTING, "Feed I Equinix NY5, Testing" },
};

/* The published endpoint a frame was sent to, NULL for any other destination */
static const iexequities_tops_endpoint *
iexequities_tops_endpoint_of(packet_info *pinfo)
{
    if (pinfo->net_dst.type != AT_IPv4 || pinfo->net_dst.len != 4) {
        return NULL;
    }

    for (size_t index = 0; index < array_length(iexequities_tops_endpoints); index++) {
        const iexequities_tops_endpoint *endpoint = &iexequities_tops_endpoints[index];

        if (pinfo->destport == endpoint->port && memcmp(pinfo->net_dst.data, endpoint->address, 4) == 0) {
            return endpoint;
        }
    }

    return NULL;
}

/* Environment of a frame, from the preference or the published endpoint
   it was sent to, production for any other destination */
static int
iexequities_tops_environment(const iexequities_tops_endpoint *endpoint)
{
    if (iexequities_tops_pref_environment != IEXEQUITIES_TOPS_ENVIRONMENT_AUTOMATIC) {
        return iexequities_tops_pref_environment;
    }

    if (endpoint == NULL) {
        return IEXEQUITIES_TOPS_ENVIRONMENT_PRODUCTION;
    }

    return endpoint->environment;
}

/*
 * IexEquities Tops Fields
 */

/* Adjusted Poc Price */
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_NAME        "Adjusted Poc Price"
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_DESCRIPTION "Corporate action adjusted previous official closing price"
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_FILTER      "iexequities.tops.adjustedpocprice"
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_adjusted_poc_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_adjusted_poc_price, tvb, offset, IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_SIZE, IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_SIZE;
}

/* Ask Price */
#define IEXEQUITIES_TOPS_ASK_PRICE_NAME        "Ask Price"
#define IEXEQUITIES_TOPS_ASK_PRICE_DESCRIPTION "Best quoted ask price"
#define IEXEQUITIES_TOPS_ASK_PRICE_FILTER      "iexequities.tops.askprice"
#define IEXEQUITIES_TOPS_ASK_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_ASK_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_ASK_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_ASK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_ASK_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_ask_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_ask_price, tvb, offset, IEXEQUITIES_TOPS_ASK_PRICE_SIZE, IEXEQUITIES_TOPS_ASK_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_ASK_PRICE_SIZE;
}

/* Ask Size */
#define IEXEQUITIES_TOPS_ASK_SIZE_NAME        "Ask Size"
#define IEXEQUITIES_TOPS_ASK_SIZE_DESCRIPTION "Aggregate quoted best ask size"
#define IEXEQUITIES_TOPS_ASK_SIZE_FILTER      "iexequities.tops.asksize"
#define IEXEQUITIES_TOPS_ASK_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_ASK_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_ASK_SIZE_MASK        0x0
#define IEXEQUITIES_TOPS_ASK_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_ASK_SIZE_SIZE        4

static unsigned
parse_iexequities_tops_ask_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_ask_size, tvb, offset, IEXEQUITIES_TOPS_ASK_SIZE_SIZE, IEXEQUITIES_TOPS_ASK_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPS_ASK_SIZE_SIZE;
}

/* Auction Book Clearing Price */
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_NAME        "Auction Book Clearing Price"
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_DESCRIPTION "Clearing price using orders on the Auction Book"
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_FILTER      "iexequities.tops.auctionbookclearingprice"
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_auction_book_clearing_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_auction_book_clearing_price, tvb, offset, IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_SIZE, IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_SIZE;
}

/* Auction Type */
#define IEXEQUITIES_TOPS_AUCTION_TYPE_NAME        "Auction Type"
#define IEXEQUITIES_TOPS_AUCTION_TYPE_DESCRIPTION "Auction type identifier"
#define IEXEQUITIES_TOPS_AUCTION_TYPE_FILTER      "iexequities.tops.auctiontype"
#define IEXEQUITIES_TOPS_AUCTION_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_AUCTION_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_AUCTION_TYPE_MASK        0x0
#define IEXEQUITIES_TOPS_AUCTION_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_AUCTION_TYPE_SIZE        1

static const value_string iexequities_tops_auction_type_vals[] = {
    { 'O', "Opening Auction" },
    { 'C', "Closing Auction" },
    { 'I', "Ipo Auction" },
    { 'H', "Halt Auction" },
    { 'V', "Volatility Auction" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_auction_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_auction_type, tvb, offset, IEXEQUITIES_TOPS_AUCTION_TYPE_SIZE, IEXEQUITIES_TOPS_AUCTION_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPS_AUCTION_TYPE_SIZE;
}

/* Bid Price */
#define IEXEQUITIES_TOPS_BID_PRICE_NAME        "Bid Price"
#define IEXEQUITIES_TOPS_BID_PRICE_DESCRIPTION "Best quoted bid price"
#define IEXEQUITIES_TOPS_BID_PRICE_FILTER      "iexequities.tops.bidprice"
#define IEXEQUITIES_TOPS_BID_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_BID_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_BID_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_BID_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_BID_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_bid_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_bid_price, tvb, offset, IEXEQUITIES_TOPS_BID_PRICE_SIZE, IEXEQUITIES_TOPS_BID_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_BID_PRICE_SIZE;
}

/* Bid Size */
#define IEXEQUITIES_TOPS_BID_SIZE_NAME        "Bid Size"
#define IEXEQUITIES_TOPS_BID_SIZE_DESCRIPTION "Aggregate quoted best bid size"
#define IEXEQUITIES_TOPS_BID_SIZE_FILTER      "iexequities.tops.bidsize"
#define IEXEQUITIES_TOPS_BID_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_BID_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_BID_SIZE_MASK        0x0
#define IEXEQUITIES_TOPS_BID_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_BID_SIZE_SIZE        4

static unsigned
parse_iexequities_tops_bid_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_bid_size, tvb, offset, IEXEQUITIES_TOPS_BID_SIZE_SIZE, IEXEQUITIES_TOPS_BID_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPS_BID_SIZE_SIZE;
}

/* Channel Id */
#define IEXEQUITIES_TOPS_CHANNEL_ID_NAME        "Channel Id"
#define IEXEQUITIES_TOPS_CHANNEL_ID_DESCRIPTION "Identifies the stream of bytes sequenced messages"
#define IEXEQUITIES_TOPS_CHANNEL_ID_FILTER      "iexequities.tops.channelid"
#define IEXEQUITIES_TOPS_CHANNEL_ID_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_CHANNEL_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_CHANNEL_ID_MASK        0x0
#define IEXEQUITIES_TOPS_CHANNEL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_CHANNEL_ID_SIZE        4

static unsigned
parse_iexequities_tops_channel_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_channel_id, tvb, offset, IEXEQUITIES_TOPS_CHANNEL_ID_SIZE, IEXEQUITIES_TOPS_CHANNEL_ID_ENCODING);

    return offset + IEXEQUITIES_TOPS_CHANNEL_ID_SIZE;
}

/* Collar Reference Price */
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_NAME        "Collar Reference Price"
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_DESCRIPTION "Reference priced used for the auction collar, if any"
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_FILTER      "iexequities.tops.collarreferenceprice"
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_collar_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_collar_reference_price, tvb, offset, IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_SIZE, IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_SIZE;
}

/* Detail */
#define IEXEQUITIES_TOPS_DETAIL_NAME        "Detail"
#define IEXEQUITIES_TOPS_DETAIL_DESCRIPTION "Detail of the Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_TOPS_DETAIL_FILTER      "iexequities.tops.detail"
#define IEXEQUITIES_TOPS_DETAIL_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_DETAIL_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_DETAIL_MASK        0x0
#define IEXEQUITIES_TOPS_DETAIL_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_DETAIL_SIZE        1

static const value_string iexequities_tops_detail_vals[] = {
    { ' ', "No Price Test In Place" },
    { 'A', "Activated" },
    { 'C', "Continued" },
    { 'D', "Deactivated" },
    { 'N', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_detail(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_detail, tvb, offset, IEXEQUITIES_TOPS_DETAIL_SIZE, IEXEQUITIES_TOPS_DETAIL_ENCODING);

    return offset + IEXEQUITIES_TOPS_DETAIL_SIZE;
}

/* Etp */
#define IEXEQUITIES_TOPS_ETP_NAME        "Etp"
#define IEXEQUITIES_TOPS_ETP_DESCRIPTION "Symbol is an ETP"
#define IEXEQUITIES_TOPS_ETP_FILTER      "iexequities.tops.etp"
#define IEXEQUITIES_TOPS_ETP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_ETP_DISPLAY     8
#define IEXEQUITIES_TOPS_ETP_MASK        0x20

/* Extended Hours */
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_NAME        "Extended Hours"
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_DESCRIPTION "Extended Hours Trade"
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_FILTER      "iexequities.tops.extendedhours"
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_DISPLAY     8
#define IEXEQUITIES_TOPS_EXTENDED_HOURS_MASK        0x40

/* Extension Number */
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_NAME        "Extension Number"
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_DESCRIPTION "Number of extensions an auction received"
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_FILTER      "iexequities.tops.extensionnumber"
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_EXTENSION_NUMBER_SIZE        1

static unsigned
parse_iexequities_tops_extension_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_extension_number, tvb, offset, IEXEQUITIES_TOPS_EXTENSION_NUMBER_SIZE, IEXEQUITIES_TOPS_EXTENSION_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPS_EXTENSION_NUMBER_SIZE;
}

/* First Message Sequence Number */
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME        "First Message Sequence Number"
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION "Sequence of the first message in the segment"
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER      "iexequities.tops.firstmessagesequencenumber"
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK        0x0
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_iexequities_tops_first_message_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_first_message_sequence_number, tvb, offset, IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE, IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_ENCODING);

    return offset + IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_SIZE;
}

/* Imbalance Shares */
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_NAME        "Imbalance Shares"
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_DESCRIPTION "Number of unpaired shares at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_FILTER      "iexequities.tops.imbalanceshares"
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_MASK        0x0
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_IMBALANCE_SHARES_SIZE        4

static unsigned
parse_iexequities_tops_imbalance_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_imbalance_shares, tvb, offset, IEXEQUITIES_TOPS_IMBALANCE_SHARES_SIZE, IEXEQUITIES_TOPS_IMBALANCE_SHARES_ENCODING);

    return offset + IEXEQUITIES_TOPS_IMBALANCE_SHARES_SIZE;
}

/* Imbalance Side */
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_NAME        "Imbalance Side"
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_DESCRIPTION "Side of the unpaired shares at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_FILTER      "iexequities.tops.imbalanceside"
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_MASK        0x0
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_IMBALANCE_SIDE_SIZE        1

static const value_string iexequities_tops_imbalance_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'N', "None" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_imbalance_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_imbalance_side, tvb, offset, IEXEQUITIES_TOPS_IMBALANCE_SIDE_SIZE, IEXEQUITIES_TOPS_IMBALANCE_SIDE_ENCODING);

    return offset + IEXEQUITIES_TOPS_IMBALANCE_SIDE_SIZE;
}

/* Indicative Clearing Price */
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_NAME        "Indicative Clearing Price"
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_DESCRIPTION "Clearing price using Eligible Auction Orders"
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_FILTER      "iexequities.tops.indicativeclearingprice"
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_indicative_clearing_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_indicative_clearing_price, tvb, offset, IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_SIZE, IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_SIZE;
}

/* Intermarket Sweep */
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_NAME        "Intermarket Sweep"
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_DESCRIPTION "Intermarket Sweep Order"
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_FILTER      "iexequities.tops.intermarketsweep"
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_DISPLAY     8
#define IEXEQUITIES_TOPS_INTERMARKET_SWEEP_MASK        0x80

/* Lower Auction Collar */
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_NAME        "Lower Auction Collar"
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_DESCRIPTION "Lower threshold price of the auction collar, if any"
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_FILTER      "iexequities.tops.lowerauctioncollar"
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_MASK        0x0
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_SIZE        8

static unsigned
parse_iexequities_tops_lower_auction_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_lower_auction_collar, tvb, offset, IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_SIZE, IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_ENCODING);

    return offset + IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_SIZE;
}

/* Luld Tier */
#define IEXEQUITIES_TOPS_LULD_TIER_NAME        "Luld Tier"
#define IEXEQUITIES_TOPS_LULD_TIER_DESCRIPTION "Indicates which Limit Up-Limit Down price band calculation parameter is to be used"
#define IEXEQUITIES_TOPS_LULD_TIER_FILTER      "iexequities.tops.luldtier"
#define IEXEQUITIES_TOPS_LULD_TIER_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_LULD_TIER_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_LULD_TIER_MASK        0x0
#define IEXEQUITIES_TOPS_LULD_TIER_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_LULD_TIER_SIZE        1

static const value_string iexequities_tops_luld_tier_vals[] = {
    { 0, "Not Applicable" },
    { 1, "Tier 1 Nms Stock" },
    { 2, "Tier 2 Nms Stock" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_luld_tier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_luld_tier, tvb, offset, IEXEQUITIES_TOPS_LULD_TIER_SIZE, IEXEQUITIES_TOPS_LULD_TIER_ENCODING);

    return offset + IEXEQUITIES_TOPS_LULD_TIER_SIZE;
}

/* Market Session */
#define IEXEQUITIES_TOPS_MARKET_SESSION_NAME        "Market Session"
#define IEXEQUITIES_TOPS_MARKET_SESSION_DESCRIPTION "Market Session Flag"
#define IEXEQUITIES_TOPS_MARKET_SESSION_FILTER      "iexequities.tops.marketsession"
#define IEXEQUITIES_TOPS_MARKET_SESSION_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_MARKET_SESSION_DISPLAY     8
#define IEXEQUITIES_TOPS_MARKET_SESSION_MASK        0x40

/* Message Count values the dispatch switches on */
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_HEARTBEAT 0

/* Message Count */
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_NAME        "Message Count"
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_DESCRIPTION "Number of messages in the payload"
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_FILTER      "iexequities.tops.messagecount"
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_TYPE        FT_UINT16
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_MASK        0x0
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_MESSAGE_COUNT_SIZE        2

static unsigned
parse_iexequities_tops_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_message_count, tvb, offset, IEXEQUITIES_TOPS_MESSAGE_COUNT_SIZE, IEXEQUITIES_TOPS_MESSAGE_COUNT_ENCODING);

    return offset + IEXEQUITIES_TOPS_MESSAGE_COUNT_SIZE;
}

/* Message Length */
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_NAME        "Message Length"
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_DESCRIPTION "Length of the message"
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_FILTER      "iexequities.tops.messagelength"
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_iexequities_tops_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_message_length, tvb, offset, IEXEQUITIES_TOPS_MESSAGE_LENGTH_SIZE, IEXEQUITIES_TOPS_MESSAGE_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPS_MESSAGE_LENGTH_SIZE;
}

/* Message Protocol Id */
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_NAME        "Message Protocol Id"
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_DESCRIPTION "Unique identifier of the higher layer protocol"
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_FILTER      "iexequities.tops.messageprotocolid"
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_TYPE        FT_UINT16
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_MASK        0x0
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_SIZE        2

static unsigned
parse_iexequities_tops_message_protocol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_message_protocol_id, tvb, offset, IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_SIZE, IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_ENCODING);

    return offset + IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_SIZE;
}

/* Message Type values the dispatch switches on */
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT                 'S'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY           'D'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS               'H'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR   'I'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS      'O'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS 'P'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE                 'Q'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT                 'T'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE               'X'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK                  'B'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION          'A'
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_EVENT               'E'

/* Message Type */
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_NAME        "Message Type"
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_DESCRIPTION "Code identifying this message type"
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_FILTER      "iexequities.tops.messagetype"
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_MASK        0x0
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_MESSAGE_TYPE_SIZE        1

static const value_string iexequities_tops_message_type_vals[] = {
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE, "Official Price Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION, "Auction Information Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_EVENT, "Security Event Message" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_message_type, tvb, offset, IEXEQUITIES_TOPS_MESSAGE_TYPE_SIZE, IEXEQUITIES_TOPS_MESSAGE_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPS_MESSAGE_TYPE_SIZE;
}

/* Odd Lot */
#define IEXEQUITIES_TOPS_ODD_LOT_NAME        "Odd Lot"
#define IEXEQUITIES_TOPS_ODD_LOT_DESCRIPTION "Odd Lot"
#define IEXEQUITIES_TOPS_ODD_LOT_FILTER      "iexequities.tops.oddlot"
#define IEXEQUITIES_TOPS_ODD_LOT_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_ODD_LOT_DISPLAY     8
#define IEXEQUITIES_TOPS_ODD_LOT_MASK        0x20

/* Official Price */
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_NAME        "Official Price"
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_DESCRIPTION "Official opening or closing price, as specified"
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_FILTER      "iexequities.tops.officialprice"
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_OFFICIAL_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_official_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_official_price, tvb, offset, IEXEQUITIES_TOPS_OFFICIAL_PRICE_SIZE, IEXEQUITIES_TOPS_OFFICIAL_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_OFFICIAL_PRICE_SIZE;
}

/* Operational Halt Status */
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_NAME        "Operational Halt Status"
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_DESCRIPTION "Operational halt status identifier"
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_FILTER      "iexequities.tops.operationalhaltstatus"
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_MASK        0x0
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_SIZE        1

static const value_string iexequities_tops_operational_halt_status_vals[] = {
    { 'O', "Iex Specific Operational Trading Halt" },
    { 'N', "Not Operationally Halted On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_operational_halt_status, tvb, offset, IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_SIZE, IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_SIZE;
}

/* Paired Shares */
#define IEXEQUITIES_TOPS_PAIRED_SHARES_NAME        "Paired Shares"
#define IEXEQUITIES_TOPS_PAIRED_SHARES_DESCRIPTION "Number of shares paired at the Reference Price using orders on the Auction Book"
#define IEXEQUITIES_TOPS_PAIRED_SHARES_FILTER      "iexequities.tops.pairedshares"
#define IEXEQUITIES_TOPS_PAIRED_SHARES_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_PAIRED_SHARES_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_PAIRED_SHARES_MASK        0x0
#define IEXEQUITIES_TOPS_PAIRED_SHARES_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_PAIRED_SHARES_SIZE        4

static unsigned
parse_iexequities_tops_paired_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_paired_shares, tvb, offset, IEXEQUITIES_TOPS_PAIRED_SHARES_SIZE, IEXEQUITIES_TOPS_PAIRED_SHARES_ENCODING);

    return offset + IEXEQUITIES_TOPS_PAIRED_SHARES_SIZE;
}

/* Payload Length */
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_NAME        "Payload Length"
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_DESCRIPTION "Byte length of the payload"
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_FILTER      "iexequities.tops.payloadlength"
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_TYPE        FT_UINT16
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_MASK        0x0
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_PAYLOAD_LENGTH_SIZE        2

static unsigned
parse_iexequities_tops_payload_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_payload_length, tvb, offset, IEXEQUITIES_TOPS_PAYLOAD_LENGTH_SIZE, IEXEQUITIES_TOPS_PAYLOAD_LENGTH_ENCODING);

    return offset + IEXEQUITIES_TOPS_PAYLOAD_LENGTH_SIZE;
}

/* Price */
#define IEXEQUITIES_TOPS_PRICE_NAME        "Price"
#define IEXEQUITIES_TOPS_PRICE_DESCRIPTION "Trade price"
#define IEXEQUITIES_TOPS_PRICE_FILTER      "iexequities.tops.price"
#define IEXEQUITIES_TOPS_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_price, tvb, offset, IEXEQUITIES_TOPS_PRICE_SIZE, IEXEQUITIES_TOPS_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_PRICE_SIZE;
}

/* Price Type */
#define IEXEQUITIES_TOPS_PRICE_TYPE_NAME        "Price Type"
#define IEXEQUITIES_TOPS_PRICE_TYPE_DESCRIPTION "Price type identifier"
#define IEXEQUITIES_TOPS_PRICE_TYPE_FILTER      "iexequities.tops.pricetype"
#define IEXEQUITIES_TOPS_PRICE_TYPE_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_PRICE_TYPE_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_PRICE_TYPE_MASK        0x0
#define IEXEQUITIES_TOPS_PRICE_TYPE_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_PRICE_TYPE_SIZE        1

static const value_string iexequities_tops_price_type_vals[] = {
    { 'Q', "Iex Official Opening Price" },
    { 'M', "Iex Official Closing Price" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_price_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_price_type, tvb, offset, IEXEQUITIES_TOPS_PRICE_TYPE_SIZE, IEXEQUITIES_TOPS_PRICE_TYPE_ENCODING);

    return offset + IEXEQUITIES_TOPS_PRICE_TYPE_SIZE;
}

/* Reason */
#define IEXEQUITIES_TOPS_REASON_NAME        "Reason"
#define IEXEQUITIES_TOPS_REASON_DESCRIPTION "Reason for the trading status change"
#define IEXEQUITIES_TOPS_REASON_FILTER      "iexequities.tops.reason"
#define IEXEQUITIES_TOPS_REASON_TYPE        FT_STRING
#define IEXEQUITIES_TOPS_REASON_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPS_REASON_MASK        0x0
#define IEXEQUITIES_TOPS_REASON_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_REASON_SIZE        4

static unsigned
parse_iexequities_tops_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_reason, tvb, offset, IEXEQUITIES_TOPS_REASON_SIZE, IEXEQUITIES_TOPS_REASON_ENCODING);

    return offset + IEXEQUITIES_TOPS_REASON_SIZE;
}

/* Reference Price */
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_NAME        "Reference Price"
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_DESCRIPTION "Clearing price at or within the Reference Price Range using orders on the Auction Book"
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_FILTER      "iexequities.tops.referenceprice"
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_MASK        0x0
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_REFERENCE_PRICE_SIZE        8

static unsigned
parse_iexequities_tops_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_reference_price, tvb, offset, IEXEQUITIES_TOPS_REFERENCE_PRICE_SIZE, IEXEQUITIES_TOPS_REFERENCE_PRICE_ENCODING);

    return offset + IEXEQUITIES_TOPS_REFERENCE_PRICE_SIZE;
}

/* Reserved */
#define IEXEQUITIES_TOPS_RESERVED_NAME        "Reserved"
#define IEXEQUITIES_TOPS_RESERVED_DESCRIPTION "Reserved byte"
#define IEXEQUITIES_TOPS_RESERVED_FILTER      "iexequities.tops.reserved"
#define IEXEQUITIES_TOPS_RESERVED_TYPE        FT_BYTES
#define IEXEQUITIES_TOPS_RESERVED_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPS_RESERVED_MASK        0x0
#define IEXEQUITIES_TOPS_RESERVED_ENCODING    ENC_NA
#define IEXEQUITIES_TOPS_RESERVED_SIZE        1

static unsigned
parse_iexequities_tops_reserved(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_reserved, tvb, offset, IEXEQUITIES_TOPS_RESERVED_SIZE, IEXEQUITIES_TOPS_RESERVED_ENCODING);

    return offset + IEXEQUITIES_TOPS_RESERVED_SIZE;
}

/* Reserved 4 */
#define IEXEQUITIES_TOPS_RESERVED_4_NAME        "Reserved 4"
#define IEXEQUITIES_TOPS_RESERVED_4_DESCRIPTION "Reserved bytes"
#define IEXEQUITIES_TOPS_RESERVED_4_FILTER      "iexequities.tops.reserved4"
#define IEXEQUITIES_TOPS_RESERVED_4_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_RESERVED_4_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_RESERVED_4_MASK        0x0
#define IEXEQUITIES_TOPS_RESERVED_4_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_RESERVED_4_SIZE        4

static unsigned
parse_iexequities_tops_reserved_4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_reserved_4, tvb, offset, IEXEQUITIES_TOPS_RESERVED_4_SIZE, IEXEQUITIES_TOPS_RESERVED_4_ENCODING);

    return offset + IEXEQUITIES_TOPS_RESERVED_4_SIZE;
}

/* Retail Liquidity Indicator */
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_NAME        "Retail Liquidity Indicator"
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION "Retail Liquidity Indicator identifier"
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_FILTER      "iexequities.tops.retailliquidityindicator"
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_MASK        0x0
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_SIZE        1

static const value_string iexequities_tops_retail_liquidity_indicator_vals[] = {
    { ' ', "Not Applicable" },
    { 'A', "Buy Interest" },
    { 'B', "Sell Interest" },
    { 'C', "Buy And Sell Interest" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_retail_liquidity_indicator, tvb, offset, IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_SIZE, IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_ENCODING);

    return offset + IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_SIZE;
}

/* Round Lot Size */
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_NAME        "Round Lot Size"
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_DESCRIPTION "Number of shares that represent a round lot"
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_FILTER      "iexequities.tops.roundlotsize"
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_MASK        0x0
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_ROUND_LOT_SIZE_SIZE        4

static unsigned
parse_iexequities_tops_round_lot_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_round_lot_size, tvb, offset, IEXEQUITIES_TOPS_ROUND_LOT_SIZE_SIZE, IEXEQUITIES_TOPS_ROUND_LOT_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPS_ROUND_LOT_SIZE_SIZE;
}

/* Scheduled Auction Time */
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_NAME        "Scheduled Auction Time"
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_DESCRIPTION "Projected time of the auction match"
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_FILTER      "iexequities.tops.scheduledauctiontime"
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_MASK        0x0
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_ENCODING    ENC_TIME_SECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_SIZE        4

static unsigned
parse_iexequities_tops_scheduled_auction_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_scheduled_auction_time, tvb, offset, IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_SIZE, IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_ENCODING);

    return offset + IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_SIZE;
}

/* Security Event */
#define IEXEQUITIES_TOPS_SECURITY_EVENT_NAME        "Security Event"
#define IEXEQUITIES_TOPS_SECURITY_EVENT_DESCRIPTION "Security event identifier"
#define IEXEQUITIES_TOPS_SECURITY_EVENT_FILTER      "iexequities.tops.securityevent"
#define IEXEQUITIES_TOPS_SECURITY_EVENT_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_SECURITY_EVENT_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_SECURITY_EVENT_MASK        0x0
#define IEXEQUITIES_TOPS_SECURITY_EVENT_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_SECURITY_EVENT_SIZE        1

static const value_string iexequities_tops_security_event_vals[] = {
    { 'O', "Opening Process Complete" },
    { 'C', "Closing Process Complete" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_security_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_security_event, tvb, offset, IEXEQUITIES_TOPS_SECURITY_EVENT_SIZE, IEXEQUITIES_TOPS_SECURITY_EVENT_ENCODING);

    return offset + IEXEQUITIES_TOPS_SECURITY_EVENT_SIZE;
}

/* Send Time */
#define IEXEQUITIES_TOPS_SEND_TIME_NAME        "Send Time"
#define IEXEQUITIES_TOPS_SEND_TIME_DESCRIPTION "Send time of segment"
#define IEXEQUITIES_TOPS_SEND_TIME_FILTER      "iexequities.tops.sendtime"
#define IEXEQUITIES_TOPS_SEND_TIME_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPS_SEND_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPS_SEND_TIME_MASK        0x0
#define IEXEQUITIES_TOPS_SEND_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SEND_TIME_SIZE        8

static unsigned
parse_iexequities_tops_send_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_send_time, tvb, offset, IEXEQUITIES_TOPS_SEND_TIME_SIZE, IEXEQUITIES_TOPS_SEND_TIME_ENCODING);

    return offset + IEXEQUITIES_TOPS_SEND_TIME_SIZE;
}

/* Session Id */
#define IEXEQUITIES_TOPS_SESSION_ID_NAME        "Session Id"
#define IEXEQUITIES_TOPS_SESSION_ID_DESCRIPTION "Identifies the session"
#define IEXEQUITIES_TOPS_SESSION_ID_FILTER      "iexequities.tops.sessionid"
#define IEXEQUITIES_TOPS_SESSION_ID_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_SESSION_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_SESSION_ID_MASK        0x0
#define IEXEQUITIES_TOPS_SESSION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SESSION_ID_SIZE        4

static unsigned
parse_iexequities_tops_session_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_session_id, tvb, offset, IEXEQUITIES_TOPS_SESSION_ID_SIZE, IEXEQUITIES_TOPS_SESSION_ID_ENCODING);

    return offset + IEXEQUITIES_TOPS_SESSION_ID_SIZE;
}

/* Short Sale Price Test Status */
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_NAME        "Short Sale Price Test Status"
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION "Reg. SHO short sale price test restriction status"
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_FILTER      "iexequities.tops.shortsalepriceteststatus"
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_MASK        0x0
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_SIZE        1

static const value_string iexequities_tops_short_sale_price_test_status_vals[] = {
    { 0, "Not In Effect" },
    { 1, "In Effect" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_short_sale_price_test_status, tvb, offset, IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_SIZE, IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_SIZE;
}

/* Singleprice Cross Trade */
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_NAME        "Singleprice Cross Trade"
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_DESCRIPTION "Trade resulting from a single-price cross"
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_FILTER      "iexequities.tops.singlepricecrosstrade"
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_DISPLAY     8
#define IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_MASK        0x08

/* Size */
#define IEXEQUITIES_TOPS_SIZE_NAME        "Size"
#define IEXEQUITIES_TOPS_SIZE_DESCRIPTION "Trade volume"
#define IEXEQUITIES_TOPS_SIZE_FILTER      "iexequities.tops.size"
#define IEXEQUITIES_TOPS_SIZE_TYPE        FT_UINT32
#define IEXEQUITIES_TOPS_SIZE_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_SIZE_MASK        0x0
#define IEXEQUITIES_TOPS_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SIZE_SIZE        4

static unsigned
parse_iexequities_tops_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_size, tvb, offset, IEXEQUITIES_TOPS_SIZE_SIZE, IEXEQUITIES_TOPS_SIZE_ENCODING);

    return offset + IEXEQUITIES_TOPS_SIZE_SIZE;
}

/* Stream Offset */
#define IEXEQUITIES_TOPS_STREAM_OFFSET_NAME        "Stream Offset"
#define IEXEQUITIES_TOPS_STREAM_OFFSET_DESCRIPTION "Byte offset of the data stream"
#define IEXEQUITIES_TOPS_STREAM_OFFSET_FILTER      "iexequities.tops.streamoffset"
#define IEXEQUITIES_TOPS_STREAM_OFFSET_TYPE        FT_UINT64
#define IEXEQUITIES_TOPS_STREAM_OFFSET_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_STREAM_OFFSET_MASK        0x0
#define IEXEQUITIES_TOPS_STREAM_OFFSET_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_STREAM_OFFSET_SIZE        8

static unsigned
parse_iexequities_tops_stream_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_stream_offset, tvb, offset, IEXEQUITIES_TOPS_STREAM_OFFSET_SIZE, IEXEQUITIES_TOPS_STREAM_OFFSET_ENCODING);

    return offset + IEXEQUITIES_TOPS_STREAM_OFFSET_SIZE;
}

/* Symbol */
#define IEXEQUITIES_TOPS_SYMBOL_NAME        "Symbol"
#define IEXEQUITIES_TOPS_SYMBOL_DESCRIPTION "Security identifier"
#define IEXEQUITIES_TOPS_SYMBOL_FILTER      "iexequities.tops.symbol"
#define IEXEQUITIES_TOPS_SYMBOL_TYPE        FT_STRING
#define IEXEQUITIES_TOPS_SYMBOL_DISPLAY     BASE_NONE
#define IEXEQUITIES_TOPS_SYMBOL_MASK        0x0
#define IEXEQUITIES_TOPS_SYMBOL_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_SYMBOL_SIZE        8

static unsigned
parse_iexequities_tops_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_symbol, tvb, offset, IEXEQUITIES_TOPS_SYMBOL_SIZE, IEXEQUITIES_TOPS_SYMBOL_ENCODING);

    return offset + IEXEQUITIES_TOPS_SYMBOL_SIZE;
}

/* Symbol Availability */
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_NAME        "Symbol Availability"
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_DESCRIPTION "Symbol is halted, paused, or otherwise not available for trading on IEX"
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_FILTER      "iexequities.tops.symbolavailability"
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_DISPLAY     8
#define IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_MASK        0x80

/* System Event */
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_NAME        "System Event"
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_DESCRIPTION "System event identifier"
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_FILTER      "iexequities.tops.systemevent"
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_MASK        0x0
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_SYSTEM_EVENT_SIZE        1

static const value_string iexequities_tops_system_event_vals[] = {
    { 'O', "Start Of Messages" },
    { 'S', "Start Of System Hours" },
    { 'R', "Start Of Regular Market Hours" },
    { 'M', "End Of Regular Market Hours" },
    { 'E', "End Of System Hours" },
    { 'C', "End Of Messages" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_system_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_system_event, tvb, offset, IEXEQUITIES_TOPS_SYSTEM_EVENT_SIZE, IEXEQUITIES_TOPS_SYSTEM_EVENT_ENCODING);

    return offset + IEXEQUITIES_TOPS_SYSTEM_EVENT_SIZE;
}

/* Test Security */
#define IEXEQUITIES_TOPS_TEST_SECURITY_NAME        "Test Security"
#define IEXEQUITIES_TOPS_TEST_SECURITY_DESCRIPTION "Symbol is a test security"
#define IEXEQUITIES_TOPS_TEST_SECURITY_FILTER      "iexequities.tops.testsecurity"
#define IEXEQUITIES_TOPS_TEST_SECURITY_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_TEST_SECURITY_DISPLAY     8
#define IEXEQUITIES_TOPS_TEST_SECURITY_MASK        0x80

/* Timestamp */
#define IEXEQUITIES_TOPS_TIMESTAMP_NAME        "Timestamp"
#define IEXEQUITIES_TOPS_TIMESTAMP_DESCRIPTION "Time stamp of the system event"
#define IEXEQUITIES_TOPS_TIMESTAMP_FILTER      "iexequities.tops.timestamp"
#define IEXEQUITIES_TOPS_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define IEXEQUITIES_TOPS_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define IEXEQUITIES_TOPS_TIMESTAMP_MASK        0x0
#define IEXEQUITIES_TOPS_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_TIMESTAMP_SIZE        8

static unsigned
parse_iexequities_tops_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_timestamp, tvb, offset, IEXEQUITIES_TOPS_TIMESTAMP_SIZE, IEXEQUITIES_TOPS_TIMESTAMP_ENCODING);

    return offset + IEXEQUITIES_TOPS_TIMESTAMP_SIZE;
}

/* Trade Id */
#define IEXEQUITIES_TOPS_TRADE_ID_NAME        "Trade Id"
#define IEXEQUITIES_TOPS_TRADE_ID_DESCRIPTION "IEX Generated Identifier"
#define IEXEQUITIES_TOPS_TRADE_ID_FILTER      "iexequities.tops.tradeid"
#define IEXEQUITIES_TOPS_TRADE_ID_TYPE        FT_UINT64
#define IEXEQUITIES_TOPS_TRADE_ID_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_TRADE_ID_MASK        0x0
#define IEXEQUITIES_TOPS_TRADE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_TRADE_ID_SIZE        8

static unsigned
parse_iexequities_tops_trade_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_trade_id, tvb, offset, IEXEQUITIES_TOPS_TRADE_ID_SIZE, IEXEQUITIES_TOPS_TRADE_ID_ENCODING);

    return offset + IEXEQUITIES_TOPS_TRADE_ID_SIZE;
}

/* Trade Through Exempt */
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_NAME        "Trade Through Exempt"
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_DESCRIPTION "Trade is not subject to Rule 611"
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_FILTER      "iexequities.tops.tradethroughexempt"
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_DISPLAY     8
#define IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_MASK        0x10

/* Trading Status */
#define IEXEQUITIES_TOPS_TRADING_STATUS_NAME        "Trading Status"
#define IEXEQUITIES_TOPS_TRADING_STATUS_DESCRIPTION "Trading status identifier"
#define IEXEQUITIES_TOPS_TRADING_STATUS_FILTER      "iexequities.tops.tradingstatus"
#define IEXEQUITIES_TOPS_TRADING_STATUS_TYPE        FT_CHAR
#define IEXEQUITIES_TOPS_TRADING_STATUS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_TRADING_STATUS_MASK        0x0
#define IEXEQUITIES_TOPS_TRADING_STATUS_ENCODING    ENC_ASCII
#define IEXEQUITIES_TOPS_TRADING_STATUS_SIZE        1

static const value_string iexequities_tops_trading_status_vals[] = {
    { 'H', "Trading Halted Across All Us Equity Markets" },
    { 'O', "Trading Halt Released Into An Order Acceptance Period On Iex" },
    { 'P', "Trading Paused And Order Acceptance Period On Iex" },
    { 'T', "Trading On Iex" },
    { 0, NULL }
};

static unsigned
parse_iexequities_tops_trading_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_trading_status, tvb, offset, IEXEQUITIES_TOPS_TRADING_STATUS_SIZE, IEXEQUITIES_TOPS_TRADING_STATUS_ENCODING);

    return offset + IEXEQUITIES_TOPS_TRADING_STATUS_SIZE;
}

/* Upper Auction Collar */
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_NAME        "Upper Auction Collar"
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_DESCRIPTION "Upper threshold price of the auction collar, if any"
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_FILTER      "iexequities.tops.upperauctioncollar"
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_TYPE        FT_INT64
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_DISPLAY     BASE_CUSTOM
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_MASK        0x0
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_SIZE        8

static unsigned
parse_iexequities_tops_upper_auction_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_upper_auction_collar, tvb, offset, IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_SIZE, IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_ENCODING);

    return offset + IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_SIZE;
}

/* Version */
#define IEXEQUITIES_TOPS_VERSION_NAME        "Version"
#define IEXEQUITIES_TOPS_VERSION_DESCRIPTION "Version of transport specification"
#define IEXEQUITIES_TOPS_VERSION_FILTER      "iexequities.tops.version"
#define IEXEQUITIES_TOPS_VERSION_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_VERSION_DISPLAY     BASE_DEC
#define IEXEQUITIES_TOPS_VERSION_MASK        0x0
#define IEXEQUITIES_TOPS_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_VERSION_SIZE        1

static unsigned
parse_iexequities_tops_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_iexequities_tops_version, tvb, offset, IEXEQUITIES_TOPS_VERSION_SIZE, IEXEQUITIES_TOPS_VERSION_ENCODING);

    return offset + IEXEQUITIES_TOPS_VERSION_SIZE;
}

/* When Issued */
#define IEXEQUITIES_TOPS_WHEN_ISSUED_NAME        "When Issued"
#define IEXEQUITIES_TOPS_WHEN_ISSUED_DESCRIPTION "Symbol is a when issued security"
#define IEXEQUITIES_TOPS_WHEN_ISSUED_FILTER      "iexequities.tops.whenissued"
#define IEXEQUITIES_TOPS_WHEN_ISSUED_TYPE        FT_BOOLEAN
#define IEXEQUITIES_TOPS_WHEN_ISSUED_DISPLAY     8
#define IEXEQUITIES_TOPS_WHEN_ISSUED_MASK        0x40

/*
 * IexEquities Tops Structs
 */

/* Security Directory Flags */
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_NAME        "Security Directory Flags"
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_DESCRIPTION "Security Directory Flags"
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_FILTER      "iexequities.tops.securitydirectoryflags"
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_MASK        0x0
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_SIZE        1

static int * const iexequities_tops_security_directory_flags_fields[] = {
    &hf_iexequities_tops_test_security,
    &hf_iexequities_tops_when_issued,
    &hf_iexequities_tops_etp,
    NULL
};

static unsigned
parse_iexequities_tops_security_directory_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_tops_security_directory_flags,
        ett_iexequities_tops_security_directory_flags, iexequities_tops_security_directory_flags_fields, IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_SIZE;
}

/* Quote Update Flags */
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_NAME        "Quote Update Flags"
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_DESCRIPTION "Quote Update Flags"
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_FILTER      "iexequities.tops.quoteupdateflags"
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_MASK        0x0
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_SIZE        1

static int * const iexequities_tops_quote_update_flags_fields[] = {
    &hf_iexequities_tops_symbol_availability,
    &hf_iexequities_tops_market_session,
    NULL
};

static unsigned
parse_iexequities_tops_quote_update_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_tops_quote_update_flags,
        ett_iexequities_tops_quote_update_flags, iexequities_tops_quote_update_flags_fields, IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_SIZE;
}

/* Sale Condition Flags */
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_NAME        "Sale Condition Flags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_DESCRIPTION "Sale Condition Flags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_FILTER      "iexequities.tops.saleconditionflags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_MASK        0x0
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_SIZE        1

static int * const iexequities_tops_sale_condition_flags_fields[] = {
    &hf_iexequities_tops_intermarket_sweep,
    &hf_iexequities_tops_extended_hours,
    &hf_iexequities_tops_odd_lot,
    &hf_iexequities_tops_trade_through_exempt,
    &hf_iexequities_tops_singleprice_cross_trade,
    NULL
};

static unsigned
parse_iexequities_tops_sale_condition_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_tops_sale_condition_flags,
        ett_iexequities_tops_sale_condition_flags, iexequities_tops_sale_condition_flags_fields, IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_ENCODING);

    return offset + IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_SIZE;
}

/* Sale Condition Flags */
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_NAME        "Sale Condition Flags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_DESCRIPTION "Sale Condition Flags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_FILTER      "iexequities.tops.saleconditionflags"
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_TYPE        FT_UINT8
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_DISPLAY     BASE_HEX
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_MASK        0x0
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_ENCODING    ENC_LITTLE_ENDIAN
#define IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_SIZE        1

static int * const iexequities_tops_sale_condition_flags_v156_fields[] = {
    &hf_iexequities_tops_intermarket_sweep,
    &hf_iexequities_tops_extended_hours,
    &hf_iexequities_tops_odd_lot,
    &hf_iexequities_tops_trade_through_exempt,
    NULL
};

static unsigned
parse_iexequities_tops_sale_condition_flags_v156(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_iexequities_tops_sale_condition_flags_v156,
        ett_iexequities_tops_sale_condition_flags_v156, iexequities_tops_sale_condition_flags_v156_fields, IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_ENCODING);

    return offset + IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_iexequities_tops_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_quote_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_trade_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_official_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_auction_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_security_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_trade_report_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_trade_break_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_iexequities_tops_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_iexequities_tops_message_data_v164(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_iexequities_tops_message_data_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);

/* Message Header */
static unsigned
dissect_iexequities_tops_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (iexequities_tops_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_iexequities_tops_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_iexequities_tops_message_length(tvb, pinfo, group, offset);
    offset = parse_iexequities_tops_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* System Event Message */
static unsigned
dissect_iexequities_tops_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_system_event(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);

    return offset;
}

/* Security Directory Message */
static unsigned
dissect_iexequities_tops_security_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_security_directory_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_adjusted_poc_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_luld_tier(tvb, pinfo, tree, offset);

    return offset;
}

/* Trading Status Message */
static unsigned
dissect_iexequities_tops_trading_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_trading_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Liquidity Indicator Message */
static unsigned
dissect_iexequities_tops_retail_liquidity_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Operational Halt Status Message */
static unsigned
dissect_iexequities_tops_operational_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_operational_halt_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Short Sale Price Test Status Message */
static unsigned
dissect_iexequities_tops_short_sale_price_test_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_short_sale_price_test_status(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_detail(tvb, pinfo, tree, offset);

    return offset;
}

/* Quote Update Message */
static unsigned
dissect_iexequities_tops_quote_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_quote_update_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_bid_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_bid_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_ask_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_ask_size(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Report Message */
static unsigned
dissect_iexequities_tops_trade_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Official Price Message */
static unsigned
dissect_iexequities_tops_official_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_price_type(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_official_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Break Message */
static unsigned
dissect_iexequities_tops_trade_break(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_sale_condition_flags(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_trade_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Auction Information Message */
static unsigned
dissect_iexequities_tops_auction_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_auction_type(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_reference_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_indicative_clearing_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_imbalance_side(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_extension_number(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_scheduled_auction_time(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_auction_book_clearing_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_collar_reference_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_lower_auction_collar(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_upper_auction_collar(tvb, pinfo, tree, offset);

    return offset;
}

/* Security Event Message */
static unsigned
dissect_iexequities_tops_security_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_security_event(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Report Message V156 */
static unsigned
dissect_iexequities_tops_trade_report_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_sale_condition_flags_v156(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_trade_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_reserved_4(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Break Message V156 */
static unsigned
dissect_iexequities_tops_trade_break_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_iexequities_tops_sale_condition_flags_v156(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_timestamp(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_symbol(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_size(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_price(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_trade_id(tvb, pinfo, tree, offset);
    offset = parse_iexequities_tops_reserved_4(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * IexEquities Tops Parse Trees, a dispatch per distinct branch definition
 */

static const value_string iexequities_tops_messages[] = {
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR, "Retail Liquidity Indicator Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE, "Official Price Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION, "Auction Information Message" },
    { 0, NULL }
};

/* Message Data: dispatch on message_type */
static unsigned
dissect_iexequities_tops_message_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_iexequities_tops_system_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY:
        return dissect_iexequities_tops_security_directory(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS:
        return dissect_iexequities_tops_trading_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR:
        return dissect_iexequities_tops_retail_liquidity_indicator(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS:
        return dissect_iexequities_tops_operational_halt_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS:
        return dissect_iexequities_tops_short_sale_price_test_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE:
        return dissect_iexequities_tops_quote_update(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT:
        return dissect_iexequities_tops_trade_report(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE:
        return dissect_iexequities_tops_official_price(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK:
        return dissect_iexequities_tops_trade_break(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION:
        return dissect_iexequities_tops_auction_information(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string iexequities_tops_messages_v164[] = {
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY, "Security Directory Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS, "Trading Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS, "Operational Halt Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS, "Short Sale Price Test Status Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_EVENT, "Security Event Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE, "Official Price Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION, "Auction Information Message" },
    { 0, NULL }
};

/* Message Data: dispatch on message_type */
static unsigned
dissect_iexequities_tops_message_data_v164(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_iexequities_tops_system_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY:
        return dissect_iexequities_tops_security_directory(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS:
        return dissect_iexequities_tops_trading_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS:
        return dissect_iexequities_tops_operational_halt_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS:
        return dissect_iexequities_tops_short_sale_price_test_status(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_EVENT:
        return dissect_iexequities_tops_security_event(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE:
        return dissect_iexequities_tops_quote_update(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT:
        return dissect_iexequities_tops_trade_report(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE:
        return dissect_iexequities_tops_official_price(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK:
        return dissect_iexequities_tops_trade_break(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION:
        return dissect_iexequities_tops_auction_information(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string iexequities_tops_messages_v156[] = {
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE, "Quote Update Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT, "Trade Report Message" },
    { IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK, "Trade Break Message" },
    { 0, NULL }
};

/* Message Data: dispatch on message_type */
static unsigned
dissect_iexequities_tops_message_data_v156(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE:
        return dissect_iexequities_tops_quote_update(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT:
        return dissect_iexequities_tops_trade_report_v156(tvb, pinfo, tree, offset);
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK:
        return dissect_iexequities_tops_trade_break_v156(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
iexequities_tops_show(uint32_t message_type)
{
    switch (message_type) {
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SYSTEM_EVENT:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_DIRECTORY:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADING_STATUS:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_RETAIL_LIQUIDITY_INDICATOR:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OPERATIONAL_HALT_STATUS:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SHORT_SALE_PRICE_TEST_STATUS:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_QUOTE_UPDATE:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_REPORT:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_OFFICIAL_PRICE:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_TRADE_BREAK:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_AUCTION_INFORMATION:
        return iexequities_tops_show_application_messages;
    case IEXEQUITIES_TOPS_MESSAGE_TYPE_SECURITY_EVENT:
        return iexequities_tops_show_application_messages;
    }

    return true;
}

typedef struct iexequities_tops_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
} iexequities_tops_parse;

static const iexequities_tops_parse iexequities_tops_parse_v166 = { iexequities_tops_messages, dissect_iexequities_tops_message_data };
static const iexequities_tops_parse iexequities_tops_parse_v164 = { iexequities_tops_messages_v164, dissect_iexequities_tops_message_data_v164 };
static const iexequities_tops_parse iexequities_tops_parse_v156 = { iexequities_tops_messages_v156, dissect_iexequities_tops_message_data_v156 };

/* Parse tree of the selected version */
static const iexequities_tops_parse *
iexequities_tops_parse_for(int version)
{
    switch (version) {
    case IEXEQUITIES_TOPS_VERSION_1_64:
        return &iexequities_tops_parse_v164;
    case IEXEQUITIES_TOPS_VERSION_1_56:
        return &iexequities_tops_parse_v156;
    default:
        return &iexequities_tops_parse_v166;
    }
}

/* Iextp Header */
static unsigned
dissect_iexequities_tops_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, IEXEQUITIES_TOPS_HEADER_SIZE,
        ett_iexequities_tops_header, NULL, "Iextp Header");

    offset = parse_iexequities_tops_version(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_reserved(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_message_protocol_id(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_channel_id(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_session_id(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_payload_length(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_message_count(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_stream_offset(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_first_message_sequence_number(tvb, pinfo, header, offset);
    offset = parse_iexequities_tops_send_time(tvb, pinfo, header, offset);

    return offset;
}

/* IexEquities Tops message size adjusts the declared length */
#define IEXEQUITIES_TOPS_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_iexequities_tops_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const iexequities_tops_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = iexequities_tops_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length + IEXEQUITIES_TOPS_MESSAGE_ADJUSTMENT, ett_iexequities_tops_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_iexequities_tops_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length + IEXEQUITIES_TOPS_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_iexequities_tops_length);
    }

    return message_length + IEXEQUITIES_TOPS_MESSAGE_ADJUSTMENT;
}

/* Counted messages, returns the position after the last message */
static unsigned
dissect_iexequities_tops_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t count, const iexequities_tops_parse *parse)
{
    for (uint32_t index = 0; index < count; index++) {
        offset += dissect_iexequities_tops_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_iexequities_tops(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, IEXEQUITIES_TOPS_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_iexequities_tops, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_iexequities_tops);

    const iexequities_tops_endpoint *endpoint = iexequities_tops_endpoint_of(pinfo);

    uint32_t count = tvb_get_letohs(tvb, 14);
    uint64_t seconds = tvb_get_letoh64(tvb, 32) / UINT64_C(1000000000);
    int version = iexequities_tops_version(seconds, iexequities_tops_environment(endpoint));

    proto_item_append_text(item, " %s", iexequities_tops_version_name(version));

    if (endpoint != NULL) {
        proto_item_append_text(item, ", %s", endpoint->name);
    }

    const iexequities_tops_parse *parse = iexequities_tops_parse_for(version);
    unsigned position = dissect_iexequities_tops_header(tvb, pinfo, packet, 0);

    if (count == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Heartbeat");
        return tvb_captured_length(tvb);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%u %s", count, count == 1 ? "Message" : "Messages");

    position = dissect_iexequities_tops_messages(tvb, pinfo, packet, position, count, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define IEXEQUITIES_TOPS_MINIMUM_SIZE 40

/* Message Protocol Id, each value a version pins it to */
static bool
iexequities_tops_heur_identifier(tvbuff_t *tvb)
{
    switch (tvb_get_letohs(tvb, 2)) {
    case 0x8003: /* Iex Tops, 1.66, 1.64 */
    case 0x8002: /* Iex Tops, 1.56 */
        return true;
    default:
        return false;
    }
}

/* The declared payload length accounts for the datagram exactly */
static bool
iexequities_tops_heur_payload(tvbuff_t *tvb)
{
    return IEXEQUITIES_TOPS_HEADER_SIZE + tvb_get_letohs(tvb, 12) == tvb_reported_length(tvb);
}

/* Does the frame pass every test of Packet? */
static bool
iexequities_tops_heur_accepts(tvbuff_t *tvb, packet_info *pinfo _U_)
{
    if (!iexequities_tops_heur_identifier(tvb)) {
        return false;
    }

    if (!iexequities_tops_heur_payload(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by content */
static bool
dissect_iexequities_tops_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < IEXEQUITIES_TOPS_MINIMUM_SIZE) {
        return false;
    }

    if (!iexequities_tops_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_iexequities_tops(tvb, pinfo, tree, data);

    return true;
}

/*
 * IexEquities Tops Registration
 */

void
proto_register_iexequities_tops(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_iexequities_tops_adjusted_poc_price,
            { IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_NAME,
              IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_FILTER,
              IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_TYPE,
              IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_MASK,
              IEXEQUITIES_TOPS_ADJUSTED_POC_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_ask_price,
            { IEXEQUITIES_TOPS_ASK_PRICE_NAME,
              IEXEQUITIES_TOPS_ASK_PRICE_FILTER,
              IEXEQUITIES_TOPS_ASK_PRICE_TYPE,
              IEXEQUITIES_TOPS_ASK_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_ASK_PRICE_MASK,
              IEXEQUITIES_TOPS_ASK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_ask_size,
            { IEXEQUITIES_TOPS_ASK_SIZE_NAME,
              IEXEQUITIES_TOPS_ASK_SIZE_FILTER,
              IEXEQUITIES_TOPS_ASK_SIZE_TYPE,
              IEXEQUITIES_TOPS_ASK_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_ASK_SIZE_MASK,
              IEXEQUITIES_TOPS_ASK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_auction_book_clearing_price,
            { IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_NAME,
              IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_FILTER,
              IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_TYPE,
              IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_MASK,
              IEXEQUITIES_TOPS_AUCTION_BOOK_CLEARING_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_auction_type,
            { IEXEQUITIES_TOPS_AUCTION_TYPE_NAME,
              IEXEQUITIES_TOPS_AUCTION_TYPE_FILTER,
              IEXEQUITIES_TOPS_AUCTION_TYPE_TYPE,
              IEXEQUITIES_TOPS_AUCTION_TYPE_DISPLAY,
              VALS(iexequities_tops_auction_type_vals),
              IEXEQUITIES_TOPS_AUCTION_TYPE_MASK,
              IEXEQUITIES_TOPS_AUCTION_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_bid_price,
            { IEXEQUITIES_TOPS_BID_PRICE_NAME,
              IEXEQUITIES_TOPS_BID_PRICE_FILTER,
              IEXEQUITIES_TOPS_BID_PRICE_TYPE,
              IEXEQUITIES_TOPS_BID_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_BID_PRICE_MASK,
              IEXEQUITIES_TOPS_BID_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_bid_size,
            { IEXEQUITIES_TOPS_BID_SIZE_NAME,
              IEXEQUITIES_TOPS_BID_SIZE_FILTER,
              IEXEQUITIES_TOPS_BID_SIZE_TYPE,
              IEXEQUITIES_TOPS_BID_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_BID_SIZE_MASK,
              IEXEQUITIES_TOPS_BID_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_channel_id,
            { IEXEQUITIES_TOPS_CHANNEL_ID_NAME,
              IEXEQUITIES_TOPS_CHANNEL_ID_FILTER,
              IEXEQUITIES_TOPS_CHANNEL_ID_TYPE,
              IEXEQUITIES_TOPS_CHANNEL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_CHANNEL_ID_MASK,
              IEXEQUITIES_TOPS_CHANNEL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_collar_reference_price,
            { IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_NAME,
              IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_FILTER,
              IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_TYPE,
              IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_MASK,
              IEXEQUITIES_TOPS_COLLAR_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_detail,
            { IEXEQUITIES_TOPS_DETAIL_NAME,
              IEXEQUITIES_TOPS_DETAIL_FILTER,
              IEXEQUITIES_TOPS_DETAIL_TYPE,
              IEXEQUITIES_TOPS_DETAIL_DISPLAY,
              VALS(iexequities_tops_detail_vals),
              IEXEQUITIES_TOPS_DETAIL_MASK,
              IEXEQUITIES_TOPS_DETAIL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_extension_number,
            { IEXEQUITIES_TOPS_EXTENSION_NUMBER_NAME,
              IEXEQUITIES_TOPS_EXTENSION_NUMBER_FILTER,
              IEXEQUITIES_TOPS_EXTENSION_NUMBER_TYPE,
              IEXEQUITIES_TOPS_EXTENSION_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_EXTENSION_NUMBER_MASK,
              IEXEQUITIES_TOPS_EXTENSION_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_first_message_sequence_number,
            { IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_NAME,
              IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_FILTER,
              IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_TYPE,
              IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_MASK,
              IEXEQUITIES_TOPS_FIRST_MESSAGE_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_imbalance_shares,
            { IEXEQUITIES_TOPS_IMBALANCE_SHARES_NAME,
              IEXEQUITIES_TOPS_IMBALANCE_SHARES_FILTER,
              IEXEQUITIES_TOPS_IMBALANCE_SHARES_TYPE,
              IEXEQUITIES_TOPS_IMBALANCE_SHARES_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_IMBALANCE_SHARES_MASK,
              IEXEQUITIES_TOPS_IMBALANCE_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_imbalance_side,
            { IEXEQUITIES_TOPS_IMBALANCE_SIDE_NAME,
              IEXEQUITIES_TOPS_IMBALANCE_SIDE_FILTER,
              IEXEQUITIES_TOPS_IMBALANCE_SIDE_TYPE,
              IEXEQUITIES_TOPS_IMBALANCE_SIDE_DISPLAY,
              VALS(iexequities_tops_imbalance_side_vals),
              IEXEQUITIES_TOPS_IMBALANCE_SIDE_MASK,
              IEXEQUITIES_TOPS_IMBALANCE_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_indicative_clearing_price,
            { IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_NAME,
              IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_FILTER,
              IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_TYPE,
              IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_MASK,
              IEXEQUITIES_TOPS_INDICATIVE_CLEARING_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_lower_auction_collar,
            { IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_NAME,
              IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_FILTER,
              IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_TYPE,
              IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_MASK,
              IEXEQUITIES_TOPS_LOWER_AUCTION_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_luld_tier,
            { IEXEQUITIES_TOPS_LULD_TIER_NAME,
              IEXEQUITIES_TOPS_LULD_TIER_FILTER,
              IEXEQUITIES_TOPS_LULD_TIER_TYPE,
              IEXEQUITIES_TOPS_LULD_TIER_DISPLAY,
              VALS(iexequities_tops_luld_tier_vals),
              IEXEQUITIES_TOPS_LULD_TIER_MASK,
              IEXEQUITIES_TOPS_LULD_TIER_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_message_count,
            { IEXEQUITIES_TOPS_MESSAGE_COUNT_NAME,
              IEXEQUITIES_TOPS_MESSAGE_COUNT_FILTER,
              IEXEQUITIES_TOPS_MESSAGE_COUNT_TYPE,
              IEXEQUITIES_TOPS_MESSAGE_COUNT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_MESSAGE_COUNT_MASK,
              IEXEQUITIES_TOPS_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_message_length,
            { IEXEQUITIES_TOPS_MESSAGE_LENGTH_NAME,
              IEXEQUITIES_TOPS_MESSAGE_LENGTH_FILTER,
              IEXEQUITIES_TOPS_MESSAGE_LENGTH_TYPE,
              IEXEQUITIES_TOPS_MESSAGE_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_MESSAGE_LENGTH_MASK,
              IEXEQUITIES_TOPS_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_message_protocol_id,
            { IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_NAME,
              IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_FILTER,
              IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_TYPE,
              IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_MASK,
              IEXEQUITIES_TOPS_MESSAGE_PROTOCOL_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_message_type,
            { IEXEQUITIES_TOPS_MESSAGE_TYPE_NAME,
              IEXEQUITIES_TOPS_MESSAGE_TYPE_FILTER,
              IEXEQUITIES_TOPS_MESSAGE_TYPE_TYPE,
              IEXEQUITIES_TOPS_MESSAGE_TYPE_DISPLAY,
              VALS(iexequities_tops_message_type_vals),
              IEXEQUITIES_TOPS_MESSAGE_TYPE_MASK,
              IEXEQUITIES_TOPS_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_official_price,
            { IEXEQUITIES_TOPS_OFFICIAL_PRICE_NAME,
              IEXEQUITIES_TOPS_OFFICIAL_PRICE_FILTER,
              IEXEQUITIES_TOPS_OFFICIAL_PRICE_TYPE,
              IEXEQUITIES_TOPS_OFFICIAL_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_OFFICIAL_PRICE_MASK,
              IEXEQUITIES_TOPS_OFFICIAL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_operational_halt_status,
            { IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_NAME,
              IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_FILTER,
              IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_TYPE,
              IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_DISPLAY,
              VALS(iexequities_tops_operational_halt_status_vals),
              IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_MASK,
              IEXEQUITIES_TOPS_OPERATIONAL_HALT_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_paired_shares,
            { IEXEQUITIES_TOPS_PAIRED_SHARES_NAME,
              IEXEQUITIES_TOPS_PAIRED_SHARES_FILTER,
              IEXEQUITIES_TOPS_PAIRED_SHARES_TYPE,
              IEXEQUITIES_TOPS_PAIRED_SHARES_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_PAIRED_SHARES_MASK,
              IEXEQUITIES_TOPS_PAIRED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_payload_length,
            { IEXEQUITIES_TOPS_PAYLOAD_LENGTH_NAME,
              IEXEQUITIES_TOPS_PAYLOAD_LENGTH_FILTER,
              IEXEQUITIES_TOPS_PAYLOAD_LENGTH_TYPE,
              IEXEQUITIES_TOPS_PAYLOAD_LENGTH_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_PAYLOAD_LENGTH_MASK,
              IEXEQUITIES_TOPS_PAYLOAD_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_price,
            { IEXEQUITIES_TOPS_PRICE_NAME,
              IEXEQUITIES_TOPS_PRICE_FILTER,
              IEXEQUITIES_TOPS_PRICE_TYPE,
              IEXEQUITIES_TOPS_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_PRICE_MASK,
              IEXEQUITIES_TOPS_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_price_type,
            { IEXEQUITIES_TOPS_PRICE_TYPE_NAME,
              IEXEQUITIES_TOPS_PRICE_TYPE_FILTER,
              IEXEQUITIES_TOPS_PRICE_TYPE_TYPE,
              IEXEQUITIES_TOPS_PRICE_TYPE_DISPLAY,
              VALS(iexequities_tops_price_type_vals),
              IEXEQUITIES_TOPS_PRICE_TYPE_MASK,
              IEXEQUITIES_TOPS_PRICE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_reason,
            { IEXEQUITIES_TOPS_REASON_NAME,
              IEXEQUITIES_TOPS_REASON_FILTER,
              IEXEQUITIES_TOPS_REASON_TYPE,
              IEXEQUITIES_TOPS_REASON_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_REASON_MASK,
              IEXEQUITIES_TOPS_REASON_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_reference_price,
            { IEXEQUITIES_TOPS_REFERENCE_PRICE_NAME,
              IEXEQUITIES_TOPS_REFERENCE_PRICE_FILTER,
              IEXEQUITIES_TOPS_REFERENCE_PRICE_TYPE,
              IEXEQUITIES_TOPS_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_REFERENCE_PRICE_MASK,
              IEXEQUITIES_TOPS_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_reserved,
            { IEXEQUITIES_TOPS_RESERVED_NAME,
              IEXEQUITIES_TOPS_RESERVED_FILTER,
              IEXEQUITIES_TOPS_RESERVED_TYPE,
              IEXEQUITIES_TOPS_RESERVED_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_RESERVED_MASK,
              IEXEQUITIES_TOPS_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_reserved_4,
            { IEXEQUITIES_TOPS_RESERVED_4_NAME,
              IEXEQUITIES_TOPS_RESERVED_4_FILTER,
              IEXEQUITIES_TOPS_RESERVED_4_TYPE,
              IEXEQUITIES_TOPS_RESERVED_4_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_RESERVED_4_MASK,
              IEXEQUITIES_TOPS_RESERVED_4_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_retail_liquidity_indicator,
            { IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_NAME,
              IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_FILTER,
              IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_TYPE,
              IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_DISPLAY,
              VALS(iexequities_tops_retail_liquidity_indicator_vals),
              IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_MASK,
              IEXEQUITIES_TOPS_RETAIL_LIQUIDITY_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_round_lot_size,
            { IEXEQUITIES_TOPS_ROUND_LOT_SIZE_NAME,
              IEXEQUITIES_TOPS_ROUND_LOT_SIZE_FILTER,
              IEXEQUITIES_TOPS_ROUND_LOT_SIZE_TYPE,
              IEXEQUITIES_TOPS_ROUND_LOT_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_ROUND_LOT_SIZE_MASK,
              IEXEQUITIES_TOPS_ROUND_LOT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_scheduled_auction_time,
            { IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_NAME,
              IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_FILTER,
              IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_TYPE,
              IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_MASK,
              IEXEQUITIES_TOPS_SCHEDULED_AUCTION_TIME_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_security_event,
            { IEXEQUITIES_TOPS_SECURITY_EVENT_NAME,
              IEXEQUITIES_TOPS_SECURITY_EVENT_FILTER,
              IEXEQUITIES_TOPS_SECURITY_EVENT_TYPE,
              IEXEQUITIES_TOPS_SECURITY_EVENT_DISPLAY,
              VALS(iexequities_tops_security_event_vals),
              IEXEQUITIES_TOPS_SECURITY_EVENT_MASK,
              IEXEQUITIES_TOPS_SECURITY_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_send_time,
            { IEXEQUITIES_TOPS_SEND_TIME_NAME,
              IEXEQUITIES_TOPS_SEND_TIME_FILTER,
              IEXEQUITIES_TOPS_SEND_TIME_TYPE,
              IEXEQUITIES_TOPS_SEND_TIME_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SEND_TIME_MASK,
              IEXEQUITIES_TOPS_SEND_TIME_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_session_id,
            { IEXEQUITIES_TOPS_SESSION_ID_NAME,
              IEXEQUITIES_TOPS_SESSION_ID_FILTER,
              IEXEQUITIES_TOPS_SESSION_ID_TYPE,
              IEXEQUITIES_TOPS_SESSION_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SESSION_ID_MASK,
              IEXEQUITIES_TOPS_SESSION_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_short_sale_price_test_status,
            { IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_NAME,
              IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_FILTER,
              IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_TYPE,
              IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_DISPLAY,
              VALS(iexequities_tops_short_sale_price_test_status_vals),
              IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_MASK,
              IEXEQUITIES_TOPS_SHORT_SALE_PRICE_TEST_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_size,
            { IEXEQUITIES_TOPS_SIZE_NAME,
              IEXEQUITIES_TOPS_SIZE_FILTER,
              IEXEQUITIES_TOPS_SIZE_TYPE,
              IEXEQUITIES_TOPS_SIZE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SIZE_MASK,
              IEXEQUITIES_TOPS_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_stream_offset,
            { IEXEQUITIES_TOPS_STREAM_OFFSET_NAME,
              IEXEQUITIES_TOPS_STREAM_OFFSET_FILTER,
              IEXEQUITIES_TOPS_STREAM_OFFSET_TYPE,
              IEXEQUITIES_TOPS_STREAM_OFFSET_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_STREAM_OFFSET_MASK,
              IEXEQUITIES_TOPS_STREAM_OFFSET_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_symbol,
            { IEXEQUITIES_TOPS_SYMBOL_NAME,
              IEXEQUITIES_TOPS_SYMBOL_FILTER,
              IEXEQUITIES_TOPS_SYMBOL_TYPE,
              IEXEQUITIES_TOPS_SYMBOL_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SYMBOL_MASK,
              IEXEQUITIES_TOPS_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_system_event,
            { IEXEQUITIES_TOPS_SYSTEM_EVENT_NAME,
              IEXEQUITIES_TOPS_SYSTEM_EVENT_FILTER,
              IEXEQUITIES_TOPS_SYSTEM_EVENT_TYPE,
              IEXEQUITIES_TOPS_SYSTEM_EVENT_DISPLAY,
              VALS(iexequities_tops_system_event_vals),
              IEXEQUITIES_TOPS_SYSTEM_EVENT_MASK,
              IEXEQUITIES_TOPS_SYSTEM_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_timestamp,
            { IEXEQUITIES_TOPS_TIMESTAMP_NAME,
              IEXEQUITIES_TOPS_TIMESTAMP_FILTER,
              IEXEQUITIES_TOPS_TIMESTAMP_TYPE,
              IEXEQUITIES_TOPS_TIMESTAMP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_TIMESTAMP_MASK,
              IEXEQUITIES_TOPS_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_trade_id,
            { IEXEQUITIES_TOPS_TRADE_ID_NAME,
              IEXEQUITIES_TOPS_TRADE_ID_FILTER,
              IEXEQUITIES_TOPS_TRADE_ID_TYPE,
              IEXEQUITIES_TOPS_TRADE_ID_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_TRADE_ID_MASK,
              IEXEQUITIES_TOPS_TRADE_ID_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_trading_status,
            { IEXEQUITIES_TOPS_TRADING_STATUS_NAME,
              IEXEQUITIES_TOPS_TRADING_STATUS_FILTER,
              IEXEQUITIES_TOPS_TRADING_STATUS_TYPE,
              IEXEQUITIES_TOPS_TRADING_STATUS_DISPLAY,
              VALS(iexequities_tops_trading_status_vals),
              IEXEQUITIES_TOPS_TRADING_STATUS_MASK,
              IEXEQUITIES_TOPS_TRADING_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_upper_auction_collar,
            { IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_NAME,
              IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_FILTER,
              IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_TYPE,
              IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_DISPLAY,
              CF_FUNC(iexequities_tops_format_decimal_4_64),
              IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_MASK,
              IEXEQUITIES_TOPS_UPPER_AUCTION_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_version,
            { IEXEQUITIES_TOPS_VERSION_NAME,
              IEXEQUITIES_TOPS_VERSION_FILTER,
              IEXEQUITIES_TOPS_VERSION_TYPE,
              IEXEQUITIES_TOPS_VERSION_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_VERSION_MASK,
              IEXEQUITIES_TOPS_VERSION_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_iexequities_tops_etp,
            { IEXEQUITIES_TOPS_ETP_NAME,
              IEXEQUITIES_TOPS_ETP_FILTER,
              IEXEQUITIES_TOPS_ETP_TYPE,
              IEXEQUITIES_TOPS_ETP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_ETP_MASK,
              IEXEQUITIES_TOPS_ETP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_extended_hours,
            { IEXEQUITIES_TOPS_EXTENDED_HOURS_NAME,
              IEXEQUITIES_TOPS_EXTENDED_HOURS_FILTER,
              IEXEQUITIES_TOPS_EXTENDED_HOURS_TYPE,
              IEXEQUITIES_TOPS_EXTENDED_HOURS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_EXTENDED_HOURS_MASK,
              IEXEQUITIES_TOPS_EXTENDED_HOURS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_intermarket_sweep,
            { IEXEQUITIES_TOPS_INTERMARKET_SWEEP_NAME,
              IEXEQUITIES_TOPS_INTERMARKET_SWEEP_FILTER,
              IEXEQUITIES_TOPS_INTERMARKET_SWEEP_TYPE,
              IEXEQUITIES_TOPS_INTERMARKET_SWEEP_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_INTERMARKET_SWEEP_MASK,
              IEXEQUITIES_TOPS_INTERMARKET_SWEEP_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_market_session,
            { IEXEQUITIES_TOPS_MARKET_SESSION_NAME,
              IEXEQUITIES_TOPS_MARKET_SESSION_FILTER,
              IEXEQUITIES_TOPS_MARKET_SESSION_TYPE,
              IEXEQUITIES_TOPS_MARKET_SESSION_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_MARKET_SESSION_MASK,
              IEXEQUITIES_TOPS_MARKET_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_odd_lot,
            { IEXEQUITIES_TOPS_ODD_LOT_NAME,
              IEXEQUITIES_TOPS_ODD_LOT_FILTER,
              IEXEQUITIES_TOPS_ODD_LOT_TYPE,
              IEXEQUITIES_TOPS_ODD_LOT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_ODD_LOT_MASK,
              IEXEQUITIES_TOPS_ODD_LOT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_singleprice_cross_trade,
            { IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_NAME,
              IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_FILTER,
              IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_TYPE,
              IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_MASK,
              IEXEQUITIES_TOPS_SINGLEPRICE_CROSS_TRADE_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_symbol_availability,
            { IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_NAME,
              IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_FILTER,
              IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_TYPE,
              IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_MASK,
              IEXEQUITIES_TOPS_SYMBOL_AVAILABILITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_test_security,
            { IEXEQUITIES_TOPS_TEST_SECURITY_NAME,
              IEXEQUITIES_TOPS_TEST_SECURITY_FILTER,
              IEXEQUITIES_TOPS_TEST_SECURITY_TYPE,
              IEXEQUITIES_TOPS_TEST_SECURITY_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_TEST_SECURITY_MASK,
              IEXEQUITIES_TOPS_TEST_SECURITY_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_trade_through_exempt,
            { IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_NAME,
              IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_FILTER,
              IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_TYPE,
              IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_MASK,
              IEXEQUITIES_TOPS_TRADE_THROUGH_EXEMPT_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_when_issued,
            { IEXEQUITIES_TOPS_WHEN_ISSUED_NAME,
              IEXEQUITIES_TOPS_WHEN_ISSUED_FILTER,
              IEXEQUITIES_TOPS_WHEN_ISSUED_TYPE,
              IEXEQUITIES_TOPS_WHEN_ISSUED_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_WHEN_ISSUED_MASK,
              IEXEQUITIES_TOPS_WHEN_ISSUED_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_iexequities_tops_security_directory_flags,
            { IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_NAME,
              IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_FILTER,
              IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_TYPE,
              IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_MASK,
              IEXEQUITIES_TOPS_SECURITY_DIRECTORY_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_quote_update_flags,
            { IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_NAME,
              IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_FILTER,
              IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_TYPE,
              IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_MASK,
              IEXEQUITIES_TOPS_QUOTE_UPDATE_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_sale_condition_flags,
            { IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_NAME,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_FILTER,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_TYPE,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_MASK,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_iexequities_tops_sale_condition_flags_v156,
            { IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_NAME,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_FILTER,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_TYPE,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_DISPLAY,
              NULL,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_MASK,
              IEXEQUITIES_TOPS_SALE_CONDITION_FLAGS_V156_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_iexequities_tops,
        &ett_iexequities_tops_header,
        &ett_iexequities_tops_message,
        &ett_iexequities_tops_security_directory_flags,
        &ett_iexequities_tops_quote_update_flags,
        &ett_iexequities_tops_sale_condition_flags,
        &ett_iexequities_tops_sale_condition_flags_v156,
        &ett_iexequities_tops_message_header,
    };

    static ei_register_info ei[] = {
        { &ei_iexequities_tops_length,
            { IEXEQUITIES_TOPS_LENGTH_EXPERT_FILTER,
              IEXEQUITIES_TOPS_LENGTH_EXPERT_GROUP,
              IEXEQUITIES_TOPS_LENGTH_EXPERT_SEVERITY,
              IEXEQUITIES_TOPS_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_iexequities_tops = proto_register_protocol(IEXEQUITIES_TOPS_PROTOCOL_NAME, IEXEQUITIES_TOPS_PROTOCOL_SHORT, IEXEQUITIES_TOPS_PROTOCOL_FILTER);

    proto_register_field_array(proto_iexequities_tops, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_iexequities_tops = expert_register_protocol(proto_iexequities_tops);
    expert_register_field_array(expert_iexequities_tops, ei, array_length(ei));

    module_t *prefs = prefs_register_protocol(proto_iexequities_tops, NULL);

    prefs_register_enum_preference(
        prefs,
        IEXEQUITIES_TOPS_VERSION_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_VERSION_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_VERSION_PREFERENCE_DESCRIPTION,
        &iexequities_tops_pref_version,
        iexequities_tops_version_vals,
        false);

    prefs_register_enum_preference(
        prefs,
        IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_ENVIRONMENT_PREFERENCE_DESCRIPTION,
        &iexequities_tops_pref_environment,
        iexequities_tops_environment_vals,
        false);

    prefs_register_bool_preference(
        prefs,
        IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &iexequities_tops_show_headers);

    prefs_register_bool_preference(
        prefs,
        IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &iexequities_tops_show_application_messages);

    prefs_register_uint_preference(
        prefs,
        IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &iexequities_tops_pref_decimal_places);

    prefs_register_bool_preference(
        prefs,
        IEXEQUITIES_TOPS_INDEXES_PREFERENCE_NAME,
        IEXEQUITIES_TOPS_INDEXES_PREFERENCE_TITLE,
        IEXEQUITIES_TOPS_INDEXES_PREFERENCE_DESCRIPTION,
        &iexequities_tops_pref_show_indexes);

    iexequities_tops_handle = register_dissector(IEXEQUITIES_TOPS_PROTOCOL_FILTER, dissect_iexequities_tops, proto_iexequities_tops);
}

void
proto_reg_handoff_iexequities_tops(void)
{
    heur_dissector_add("udp", dissect_iexequities_tops_heur, "IEX TOPS over UDP",
        "iexequities_tops_udp", proto_iexequities_tops, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("udp.port", iexequities_tops_handle);
}
