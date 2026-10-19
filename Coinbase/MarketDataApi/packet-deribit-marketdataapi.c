/* packet-deribit-marketdataapi.c
 * Routines for Deribit MarketDataApi dissection
 *
 * Aggregated protocol versions: 1.0, 0.1
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Coinbase.Deribit.MarketDataApi.Sbe.v1.0
 *   Coinbase.Deribit.MarketDataApi.Sbe.v0.1
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

void proto_register_deribit_marketdataapi(void);
void proto_reg_handoff_deribit_marketdataapi(void);

static dissector_handle_t deribit_marketdataapi_handle;

static int proto_deribit_marketdataapi;

/*
 * Deribit MarketDataApi Protocol
 */

#define DERIBIT_MARKETDATAAPI_PROTOCOL_NAME "Deribit MarketDataApi"
#define DERIBIT_MARKETDATAAPI_PROTOCOL_SHORT "DERIBIT.MARKETDATAAPI"
#define DERIBIT_MARKETDATAAPI_PROTOCOL_FILTER "deribit.marketdataapi"

/*
 * Deribit MarketDataApi Header
 */

#define DERIBIT_MARKETDATAAPI_HEADER_SIZE 24 /* Packet Header */

/*
 * Deribit MarketDataApi Field Handles
 */

static int hf_deribit_marketdataapi_active_instrument_count;
static int hf_deribit_marketdataapi_base_currency;
static int hf_deribit_marketdataapi_base_increment;
static int hf_deribit_marketdataapi_begin_seq_num;
static int hf_deribit_marketdataapi_block_length;
static int hf_deribit_marketdataapi_block_rfq_id;
static int hf_deribit_marketdataapi_block_trade_id;
static int hf_deribit_marketdataapi_channel_id;
static int hf_deribit_marketdataapi_creation_time;
static int hf_deribit_marketdataapi_current_funding;
static int hf_deribit_marketdataapi_day_of_month;
static int hf_deribit_marketdataapi_deepest_price;
static int hf_deribit_marketdataapi_delivery_price;
static int hf_deribit_marketdataapi_details;
static int hf_deribit_marketdataapi_end_of_transaction;
static int hf_deribit_marketdataapi_estimated_delivery_price;
static int hf_deribit_marketdataapi_expiry_time;
static int hf_deribit_marketdataapi_fill_price;
static int hf_deribit_marketdataapi_fill_qty_mantissa;
static int hf_deribit_marketdataapi_flags;
static int hf_deribit_marketdataapi_flags_v01;
static int hf_deribit_marketdataapi_funding_8h;
static int hf_deribit_marketdataapi_implied_volatility;
static int hf_deribit_marketdataapi_increment_seq_num;
static int hf_deribit_marketdataapi_incremental_seq_num;
static int hf_deribit_marketdataapi_incremental_timestamp;
static int hf_deribit_marketdataapi_incremental_update;
static int hf_deribit_marketdataapi_index_id;
static int hf_deribit_marketdataapi_index_price;
static int hf_deribit_marketdataapi_instrument_id;
static int hf_deribit_marketdataapi_is_liquidation;
static int hf_deribit_marketdataapi_is_perpetual;
static int hf_deribit_marketdataapi_is_put_option;
static int hf_deribit_marketdataapi_is_reversed;
static int hf_deribit_marketdataapi_is_sell;
static int hf_deribit_marketdataapi_large_tick_size;
static int hf_deribit_marketdataapi_large_tick_size_0;
static int hf_deribit_marketdataapi_large_tick_size_1;
static int hf_deribit_marketdataapi_large_tick_threshold_0;
static int hf_deribit_marketdataapi_large_tick_threshold_1;
static int hf_deribit_marketdataapi_leg_instrument_id;
static int hf_deribit_marketdataapi_maker_flags;
static int hf_deribit_marketdataapi_maker_order_id;
static int hf_deribit_marketdataapi_mark_price;
static int hf_deribit_marketdataapi_match_id;
static int hf_deribit_marketdataapi_max_buy_price;
static int hf_deribit_marketdataapi_message_count;
static int hf_deribit_marketdataapi_message_count_short;
static int hf_deribit_marketdataapi_message_flags;
static int hf_deribit_marketdataapi_message_length;
static int hf_deribit_marketdataapi_min_order_quantity;
static int hf_deribit_marketdataapi_min_sell_price;
static int hf_deribit_marketdataapi_month;
static int hf_deribit_marketdataapi_name;
static int hf_deribit_marketdataapi_num_in_group;
static int hf_deribit_marketdataapi_number_of_legs;
static int hf_deribit_marketdataapi_order_id;
static int hf_deribit_marketdataapi_packet_type;
static int hf_deribit_marketdataapi_padding;
static int hf_deribit_marketdataapi_price;
static int hf_deribit_marketdataapi_price_asset;
static int hf_deribit_marketdataapi_quantity_asset;
static int hf_deribit_marketdataapi_quantity_exponent;
static int hf_deribit_marketdataapi_quantity_mantissa;
static int hf_deribit_marketdataapi_quote_currency;
static int hf_deribit_marketdataapi_ratio;
static int hf_deribit_marketdataapi_reason;
static int hf_deribit_marketdataapi_reserved_29;
static int hf_deribit_marketdataapi_reserved_30;
static int hf_deribit_marketdataapi_reserved_5;
static int hf_deribit_marketdataapi_retransmit;
static int hf_deribit_marketdataapi_retry_delay_nanos;
static int hf_deribit_marketdataapi_schema_version;
static int hf_deribit_marketdataapi_sending_time;
static int hf_deribit_marketdataapi_seq_num;
static int hf_deribit_marketdataapi_settlement_price;
static int hf_deribit_marketdataapi_snapshot;
static int hf_deribit_marketdataapi_sort_order_id;
static int hf_deribit_marketdataapi_start_of_transaction;
static int hf_deribit_marketdataapi_status;
static int hf_deribit_marketdataapi_strike_price;
static int hf_deribit_marketdataapi_symbol;
static int hf_deribit_marketdataapi_taker_flags;
static int hf_deribit_marketdataapi_taker_order_id;
static int hf_deribit_marketdataapi_template_id;
static int hf_deribit_marketdataapi_threshold_price;
static int hf_deribit_marketdataapi_tick_size;
static int hf_deribit_marketdataapi_timestamp;
static int hf_deribit_marketdataapi_total_filled_mantissa;
static int hf_deribit_marketdataapi_trade_count;
static int hf_deribit_marketdataapi_trading_status;
static int hf_deribit_marketdataapi_transact_time;
static int hf_deribit_marketdataapi_type;
static int hf_deribit_marketdataapi_underlying;
static int hf_deribit_marketdataapi_week_of_month;
static int hf_deribit_marketdataapi_year;

/*
 * Deribit MarketDataApi Subtrees
 */

static int ett_deribit_marketdataapi;
static int ett_deribit_marketdataapi_header;
static int ett_deribit_marketdataapi_message;
static int ett_deribit_marketdataapi_packet_type;
static int ett_deribit_marketdataapi_message_flags;
static int ett_deribit_marketdataapi_flags;
static int ett_deribit_marketdataapi_taker_flags;
static int ett_deribit_marketdataapi_maker_flags;
static int ett_deribit_marketdataapi_flags_v01;
static int ett_deribit_marketdataapi_md_message_header;
static int ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups;
static int ett_deribit_marketdataapi_group_size_encoding;
static int ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group;
static int ett_deribit_marketdataapi_instrument_definition_message_legs_groups;
static int ett_deribit_marketdataapi_instrument_definition_message_legs_group;
static int ett_deribit_marketdataapi_logical_expiry;

/*
 * Deribit MarketDataApi Expert Information
 */

/* Message length does not account for the parsed fields */
#define DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_FILTER "deribit.marketdataapi.length.invalid"
#define DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_GROUP PI_MALFORMED
#define DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_SEVERITY PI_ERROR
#define DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_deribit_marketdataapi_length;

/*
 * Deribit MarketDataApi Preferences
 */

#define DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_NAME "version"
#define DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_TITLE "Protocol version"
#define DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define DERIBIT_MARKETDATAAPI_VERSION_AUTOMATIC 0
#define DERIBIT_MARKETDATAAPI_VERSION_1_0     1
#define DERIBIT_MARKETDATAAPI_VERSION_0_1     2

static const enum_val_t deribit_marketdataapi_version_vals[] = {
    { "automatic", "Automatic (by send time)", DERIBIT_MARKETDATAAPI_VERSION_AUTOMATIC },
    { "v1.0", "1.0", DERIBIT_MARKETDATAAPI_VERSION_1_0 },
    { "v0.1", "0.1", DERIBIT_MARKETDATAAPI_VERSION_0_1 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
deribit_marketdataapi_version_name(int version)
{
    switch (version) {
    case DERIBIT_MARKETDATAAPI_VERSION_1_0:
        return "1.0";
    case DERIBIT_MARKETDATAAPI_VERSION_0_1:
        return "0.1";
    }

    return "";
}

static int deribit_marketdataapi_pref_version = DERIBIT_MARKETDATAAPI_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define DERIBIT_MARKETDATAAPI_EFFECTIVE_1_0 UINT64_C(1778025600) /* 2026-05-06 */

/* Show preferences, one per message and struct */
#define DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_NAME "show.structs"
#define DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_TITLE "Show Structs"
#define DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION "Show Structs in the protocol tree"

static bool deribit_marketdataapi_show_headers = true;
static bool deribit_marketdataapi_show_application_messages = true;
static bool deribit_marketdataapi_show_structs = true;

/* Decimal places shown, the wire precision by default */
#define DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_NAME "decimal.places"
#define DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned deribit_marketdataapi_pref_decimal_places = 9;

/* Entries of a repeating group are numbered */
#define DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_NAME "show.indexes"
#define DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_TITLE "Show Indexes"
#define DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_DESCRIPTION "Number the entries of a repeating group in the protocol tree"

static bool deribit_marketdataapi_pref_show_indexes = true;

/*
 * Deribit MarketDataApi Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
deribit_marketdataapi_version(uint64_t seconds)
{
    if (deribit_marketdataapi_pref_version != DERIBIT_MARKETDATAAPI_VERSION_AUTOMATIC) {
        return deribit_marketdataapi_pref_version;
    }

    if (seconds >= DERIBIT_MARKETDATAAPI_EFFECTIVE_1_0) {
        return DERIBIT_MARKETDATAAPI_VERSION_1_0;
    }

    return DERIBIT_MARKETDATAAPI_VERSION_0_1;
}

/* Cap the fraction at the preferred decimal places */
static void
deribit_marketdataapi_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = deribit_marketdataapi_pref_decimal_places;

    if (places >= strlen(point + 1)) {
        return;
    }

    if (places == 0) {
        *point = '\0';
        return;
    }

    point[1 + places] = '\0';
}

/* Format an implied 9 decimal place value */
static void
deribit_marketdataapi_format_decimal_9_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t units = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, units, fraction);
    }

    deribit_marketdataapi_decimal_places(buf);
}

/* Format an implied 9 decimal place value */
static void
deribit_marketdataapi_format_decimal_9_64_nullable(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }
    int64_t units = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, units, fraction);
    }

    deribit_marketdataapi_decimal_places(buf);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
deribit_marketdataapi_format_nullable_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/* Broadcast endpoints from the connectivity model */
typedef struct deribit_marketdataapi_endpoint {
    uint8_t address[4];
    uint16_t port;
    const char *name;
} deribit_marketdataapi_endpoint;

static const deribit_marketdataapi_endpoint deribit_marketdataapi_endpoints[] = {
    { { 224, 0, 12, 192 }, 4230, "Feed Sbe Market Data Snapshot BTC Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 208 }, 4230, "Feed Sbe Market Data Snapshot BTC Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 193 }, 4220, "Feed Sbe Market Data Incremental BTC Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 209 }, 4220, "Feed Sbe Market Data Incremental BTC Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 224 }, 4230, "Feed Sbe Market Data Snapshot BTC Perpetuals, Futures and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 225 }, 4220, "Feed Sbe Market Data Incremental BTC Perpetuals, Futures and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 194 }, 4230, "Feed Sbe Market Data Snapshot BTC Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 210 }, 4230, "Feed Sbe Market Data Snapshot BTC Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 195 }, 4220, "Feed Sbe Market Data Incremental BTC Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 211 }, 4220, "Feed Sbe Market Data Incremental BTC Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 226 }, 4230, "Feed Sbe Market Data Snapshot BTC Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 227 }, 4220, "Feed Sbe Market Data Incremental BTC Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 196 }, 4230, "Feed Sbe Market Data Snapshot ETH Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 212 }, 4230, "Feed Sbe Market Data Snapshot ETH Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 197 }, 4220, "Feed Sbe Market Data Incremental ETH Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 213 }, 4220, "Feed Sbe Market Data Incremental ETH Perpetuals, Futures and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 228 }, 4230, "Feed Sbe Market Data Snapshot ETH Perpetuals, Futures and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 229 }, 4220, "Feed Sbe Market Data Incremental ETH Perpetuals, Futures and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 198 }, 4230, "Feed Sbe Market Data Snapshot ETH Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 214 }, 4230, "Feed Sbe Market Data Snapshot ETH Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 199 }, 4220, "Feed Sbe Market Data Incremental ETH Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 215 }, 4220, "Feed Sbe Market Data Incremental ETH Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 230 }, 4230, "Feed Sbe Market Data Snapshot ETH Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 231 }, 4220, "Feed Sbe Market Data Incremental ETH Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 200 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 216 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 201 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 217 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 232 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 233 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Futures, Perpetuals and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 202 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 218 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 203 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 219 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Options and Option Combinations Equinix LD4" },
    { { 224, 0, 12, 234 }, 4230, "Feed Sbe Market Data Snapshot Tier 2 Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 235 }, 4220, "Feed Sbe Market Data Incremental Tier 2 Options and Option Combinations Equinix LD4, Testing" },
    { { 224, 0, 12, 204 }, 4230, "Feed Sbe Market Data Snapshot Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 220 }, 4230, "Feed Sbe Market Data Snapshot Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 205 }, 4220, "Feed Sbe Market Data Incremental Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 221 }, 4220, "Feed Sbe Market Data Incremental Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4" },
    { { 224, 0, 12, 236 }, 4230, "Feed Sbe Market Data Snapshot Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 237 }, 4220, "Feed Sbe Market Data Incremental Tier 3 Futures, Perpetuals and Future Spreads Equinix LD4, Testing" },
    { { 224, 0, 12, 206 }, 4230, "Feed Sbe Market Data Snapshot RWA and pre-IPO perpetuals Equinix LD4" },
    { { 224, 0, 12, 222 }, 4230, "Feed Sbe Market Data Snapshot RWA and pre-IPO perpetuals Equinix LD4" },
    { { 224, 0, 12, 207 }, 4220, "Feed Sbe Market Data Incremental RWA and pre-IPO perpetuals Equinix LD4" },
    { { 224, 0, 12, 223 }, 4220, "Feed Sbe Market Data Incremental RWA and pre-IPO perpetuals Equinix LD4" },
    { { 224, 0, 12, 238 }, 4230, "Feed Sbe Market Data Snapshot RWA and pre-IPO perpetuals Equinix LD4, Testing" },
    { { 224, 0, 12, 239 }, 4220, "Feed Sbe Market Data Incremental RWA and pre-IPO perpetuals Equinix LD4, Testing" },
};

/* The published endpoint a frame was sent to, NULL for any other destination */
static const deribit_marketdataapi_endpoint *
deribit_marketdataapi_endpoint_of(packet_info *pinfo)
{
    if (pinfo->net_dst.type != AT_IPv4 || pinfo->net_dst.len != 4) {
        return NULL;
    }

    for (size_t index = 0; index < array_length(deribit_marketdataapi_endpoints); index++) {
        const deribit_marketdataapi_endpoint *endpoint = &deribit_marketdataapi_endpoints[index];

        if (pinfo->destport == endpoint->port && memcmp(pinfo->net_dst.data, endpoint->address, 4) == 0) {
            return endpoint;
        }
    }

    return NULL;
}

/*
 * Deribit MarketDataApi Fields
 */

/* Active Instrument Count */
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_NAME        "Active Instrument Count"
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DESCRIPTION "activeInstrumentCount"
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_FILTER      "deribit.marketdataapi.activeinstrumentcount"
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_TYPE        FT_INT32
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE        4

static unsigned
parse_deribit_marketdataapi_active_instrument_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_active_instrument_count, tvb, offset, DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE, DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE;
}

/* Base Currency */
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_NAME        "Base Currency"
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_DESCRIPTION "baseCurrency"
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_FILTER      "deribit.marketdataapi.basecurrency"
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_TYPE        FT_STRING
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_DISPLAY     BASE_NONE
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_ENCODING    ENC_ASCII
#define DERIBIT_MARKETDATAAPI_BASE_CURRENCY_SIZE        8

static unsigned
parse_deribit_marketdataapi_base_currency(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_base_currency, tvb, offset, DERIBIT_MARKETDATAAPI_BASE_CURRENCY_SIZE, DERIBIT_MARKETDATAAPI_BASE_CURRENCY_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BASE_CURRENCY_SIZE;
}

/* Base Increment */
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_NAME        "Base Increment"
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_DESCRIPTION "baseIncrement"
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_FILTER      "deribit.marketdataapi.baseincrement"
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_BASE_INCREMENT_SIZE        8

static unsigned
parse_deribit_marketdataapi_base_increment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_base_increment, tvb, offset, DERIBIT_MARKETDATAAPI_BASE_INCREMENT_SIZE, DERIBIT_MARKETDATAAPI_BASE_INCREMENT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BASE_INCREMENT_SIZE;
}

/* Begin Seq Num */
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_NAME        "Begin Seq Num"
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_DESCRIPTION "beginSeqNum"
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_FILTER      "deribit.marketdataapi.beginseqnum"
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE        8

static unsigned
parse_deribit_marketdataapi_begin_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_begin_seq_num, tvb, offset, DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE, DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE;
}

/* Block Length */
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_NAME        "Block Length"
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_DESCRIPTION "blockLength"
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_FILTER      "deribit.marketdataapi.blocklength"
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_SIZE        2

static unsigned
parse_deribit_marketdataapi_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_block_length, tvb, offset, DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_SIZE, DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_SIZE;
}

/* Block Rfq Id */
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_NAME        "Block Rfq Id"
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_DESCRIPTION "blockRfqId"
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_FILTER      "deribit.marketdataapi.blockrfqid"
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_block_rfq_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_block_rfq_id, tvb, offset, DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_SIZE, DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_SIZE;
}

/* Block Trade Id */
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_NAME        "Block Trade Id"
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_DESCRIPTION "blockTradeId"
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_FILTER      "deribit.marketdataapi.blocktradeid"
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_block_trade_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_block_trade_id, tvb, offset, DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_SIZE, DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_SIZE;
}

/* Channel Id */
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_NAME        "Channel Id"
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_DESCRIPTION "Channel identifier for the product / instrument set"
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_FILTER      "deribit.marketdataapi.channelid"
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_TYPE        FT_INT32
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_CHANNEL_ID_SIZE        4

static unsigned
parse_deribit_marketdataapi_channel_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_channel_id, tvb, offset, DERIBIT_MARKETDATAAPI_CHANNEL_ID_SIZE, DERIBIT_MARKETDATAAPI_CHANNEL_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_CHANNEL_ID_SIZE;
}

/* Creation Time */
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_NAME        "Creation Time"
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_DESCRIPTION "creationTime"
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_FILTER      "deribit.marketdataapi.creationtime"
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_MASK        0x0
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_CREATION_TIME_SIZE        8

static unsigned
parse_deribit_marketdataapi_creation_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    if ((int64_t)tvb_get_letoh64(tvb, offset) == INT64_MIN) {
        nstime_t empty = NSTIME_INIT_ZERO;

        proto_tree_add_time_format_value(tree, hf_deribit_marketdataapi_creation_time, tvb, offset, DERIBIT_MARKETDATAAPI_CREATION_TIME_SIZE, &empty, "No Value");
    }
    else {
        proto_tree_add_item(tree, hf_deribit_marketdataapi_creation_time, tvb, offset, DERIBIT_MARKETDATAAPI_CREATION_TIME_SIZE, DERIBIT_MARKETDATAAPI_CREATION_TIME_ENCODING);
    }

    return offset + DERIBIT_MARKETDATAAPI_CREATION_TIME_SIZE;
}

/* Current Funding */
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_NAME        "Current Funding"
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_DESCRIPTION "currentFunding"
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_FILTER      "deribit.marketdataapi.currentfunding"
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_TYPE        FT_UINT64
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_MASK        0x0
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_SIZE        8

static unsigned
parse_deribit_marketdataapi_current_funding(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_current_funding, tvb, offset, DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_SIZE, DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_SIZE;
}

/* Day Of Month */
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_NAME        "Day Of Month"
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_DESCRIPTION "dayOfMonth"
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_FILTER      "deribit.marketdataapi.dayofmonth"
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_TYPE        FT_INT16
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_MASK        0x0
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_SIZE        2

static unsigned
parse_deribit_marketdataapi_day_of_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_day_of_month, tvb, offset, DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_SIZE, DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_SIZE;
}

/* Deepest Price */
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_NAME        "Deepest Price"
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_DESCRIPTION "deepestPrice"
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_FILTER      "deribit.marketdataapi.deepestprice"
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_deepest_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_deepest_price, tvb, offset, DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_SIZE, DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_SIZE;
}

/* Delivery Price */
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_NAME        "Delivery Price"
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_DESCRIPTION "deliveryPrice"
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_FILTER      "deribit.marketdataapi.deliveryprice"
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_delivery_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_delivery_price, tvb, offset, DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_SIZE, DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_SIZE;
}

/* Details */
#define DERIBIT_MARKETDATAAPI_DETAILS_NAME     "Details"
#define DERIBIT_MARKETDATAAPI_DETAILS_FILTER   "deribit.marketdataapi.details"
#define DERIBIT_MARKETDATAAPI_DETAILS_TYPE     FT_STRING
#define DERIBIT_MARKETDATAAPI_DETAILS_DISPLAY  BASE_NONE
#define DERIBIT_MARKETDATAAPI_DETAILS_MASK     0x0
#define DERIBIT_MARKETDATAAPI_DETAILS_ENCODING ENC_ASCII
#define DERIBIT_MARKETDATAAPI_DETAILS_SIZE     40

static unsigned
parse_deribit_marketdataapi_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_details, tvb, offset, DERIBIT_MARKETDATAAPI_DETAILS_SIZE, DERIBIT_MARKETDATAAPI_DETAILS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_DETAILS_SIZE;
}

/* End Of Transaction */
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_NAME        "End Of Transaction"
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_DESCRIPTION "End of transaction indicator"
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_FILTER      "deribit.marketdataapi.endoftransaction"
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_MASK        0x02

/* Estimated Delivery Price */
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_NAME        "Estimated Delivery Price"
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_DESCRIPTION "estimatedDeliveryPrice"
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_FILTER      "deribit.marketdataapi.estimateddeliveryprice"
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_estimated_delivery_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_estimated_delivery_price, tvb, offset, DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_SIZE, DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_SIZE;
}

/* Expiry Time */
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_NAME        "Expiry Time"
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_DESCRIPTION "expiryTime"
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_FILTER      "deribit.marketdataapi.expirytime"
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_MASK        0x0
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_EXPIRY_TIME_SIZE        8

static unsigned
parse_deribit_marketdataapi_expiry_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_expiry_time, tvb, offset, DERIBIT_MARKETDATAAPI_EXPIRY_TIME_SIZE, DERIBIT_MARKETDATAAPI_EXPIRY_TIME_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_EXPIRY_TIME_SIZE;
}

/* Fill Price */
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_NAME        "Fill Price"
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_DESCRIPTION "fillPrice"
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_FILTER      "deribit.marketdataapi.fillprice"
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_FILL_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_fill_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_fill_price, tvb, offset, DERIBIT_MARKETDATAAPI_FILL_PRICE_SIZE, DERIBIT_MARKETDATAAPI_FILL_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_FILL_PRICE_SIZE;
}

/* Fill Qty Mantissa */
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_NAME        "Fill Qty Mantissa"
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_DESCRIPTION "fillQtyMantissa"
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_FILTER      "deribit.marketdataapi.fillqtymantissa"
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_MASK        0x0
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_SIZE        8

static unsigned
parse_deribit_marketdataapi_fill_qty_mantissa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_fill_qty_mantissa, tvb, offset, DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_SIZE, DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_SIZE;
}

/* Funding 8h */
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_NAME        "Funding 8h"
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_DESCRIPTION "funding8h"
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_FILTER      "deribit.marketdataapi.funding8h"
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_TYPE        FT_UINT64
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_MASK        0x0
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_FUNDING_8H_SIZE        8

static unsigned
parse_deribit_marketdataapi_funding_8h(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_funding_8h, tvb, offset, DERIBIT_MARKETDATAAPI_FUNDING_8H_SIZE, DERIBIT_MARKETDATAAPI_FUNDING_8H_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_FUNDING_8H_SIZE;
}

/* Implied Volatility */
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_NAME        "Implied Volatility"
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_DESCRIPTION "impliedVolatility"
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_FILTER      "deribit.marketdataapi.impliedvolatility"
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_TYPE        FT_UINT64
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_MASK        0x0
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_SIZE        8

static unsigned
parse_deribit_marketdataapi_implied_volatility(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_implied_volatility, tvb, offset, DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_SIZE, DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_SIZE;
}

/* Increment Seq Num */
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_NAME        "Increment Seq Num"
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_DESCRIPTION "incrementSeqNum"
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_FILTER      "deribit.marketdataapi.incrementseqnum"
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_SIZE        8

static unsigned
parse_deribit_marketdataapi_increment_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_increment_seq_num, tvb, offset, DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_SIZE, DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_SIZE;
}

/* Incremental Seq Num */
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_NAME        "Incremental Seq Num"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_DESCRIPTION "incrementalSeqNum"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_FILTER      "deribit.marketdataapi.incrementalseqnum"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_SIZE        8

static unsigned
parse_deribit_marketdataapi_incremental_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_incremental_seq_num, tvb, offset, DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_SIZE, DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_SIZE;
}

/* Incremental Timestamp */
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_NAME        "Incremental Timestamp"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_DESCRIPTION "incrementalTimestamp"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_FILTER      "deribit.marketdataapi.incrementaltimestamp"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_SIZE        8

static unsigned
parse_deribit_marketdataapi_incremental_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_incremental_timestamp, tvb, offset, DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_SIZE, DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_SIZE;
}

/* Incremental Update */
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_NAME        "Incremental Update"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_DESCRIPTION "Incremental update packet indicator (Bit 0)"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_FILTER      "deribit.marketdataapi.incrementalupdate"
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_MASK        0x01

/* Index Id */
#define DERIBIT_MARKETDATAAPI_INDEX_ID_NAME        "Index Id"
#define DERIBIT_MARKETDATAAPI_INDEX_ID_DESCRIPTION "indexId"
#define DERIBIT_MARKETDATAAPI_INDEX_ID_FILTER      "deribit.marketdataapi.indexid"
#define DERIBIT_MARKETDATAAPI_INDEX_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INDEX_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_INDEX_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INDEX_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INDEX_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_index_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_index_id, tvb, offset, DERIBIT_MARKETDATAAPI_INDEX_ID_SIZE, DERIBIT_MARKETDATAAPI_INDEX_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INDEX_ID_SIZE;
}

/* Index Price */
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_NAME        "Index Price"
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_DESCRIPTION "indexPrice"
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_FILTER      "deribit.marketdataapi.indexprice"
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INDEX_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_index_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_index_price, tvb, offset, DERIBIT_MARKETDATAAPI_INDEX_PRICE_SIZE, DERIBIT_MARKETDATAAPI_INDEX_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INDEX_PRICE_SIZE;
}

/* Instrument Id */
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_NAME        "Instrument Id"
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_DESCRIPTION "instrumentId"
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_FILTER      "deribit.marketdataapi.instrumentid"
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_instrument_id, tvb, offset, DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_SIZE, DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_SIZE;
}

/* Is Liquidation */
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_NAME        "Is Liquidation"
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_DESCRIPTION "isLiquidation"
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_FILTER      "deribit.marketdataapi.isliquidation"
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_MASK        0x02

/* Is Perpetual */
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_NAME        "Is Perpetual"
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_DESCRIPTION "isPerpetual"
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_FILTER      "deribit.marketdataapi.isperpetual"
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_IS_PERPETUAL_MASK        0x04

/* Is Put Option */
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_NAME        "Is Put Option"
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_DESCRIPTION "isPutOption"
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_FILTER      "deribit.marketdataapi.isputoption"
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_MASK        0x02

/* Is Reversed */
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_NAME        "Is Reversed"
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_DESCRIPTION "isReversed"
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_FILTER      "deribit.marketdataapi.isreversed"
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_IS_REVERSED_MASK        0x01

/* Is Sell */
#define DERIBIT_MARKETDATAAPI_IS_SELL_NAME        "Is Sell"
#define DERIBIT_MARKETDATAAPI_IS_SELL_DESCRIPTION "isSell"
#define DERIBIT_MARKETDATAAPI_IS_SELL_FILTER      "deribit.marketdataapi.issell"
#define DERIBIT_MARKETDATAAPI_IS_SELL_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_IS_SELL_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_IS_SELL_MASK        0x01

/* Large Tick Size */
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_NAME        "Large Tick Size"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_DESCRIPTION "largeTickSize"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_FIX         1008
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_FILTER      "deribit.marketdataapi.largeticksize"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_SIZE        8

static unsigned
parse_deribit_marketdataapi_large_tick_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_large_tick_size, tvb, offset, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_SIZE, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_SIZE;
}

/* Large Tick Size 0 */
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_NAME        "Large Tick Size 0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_DESCRIPTION "largeTickSize0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_FILTER      "deribit.marketdataapi.largeticksize0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_SIZE        8

static unsigned
parse_deribit_marketdataapi_large_tick_size_0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_large_tick_size_0, tvb, offset, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_SIZE, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_SIZE;
}

/* Large Tick Size 1 */
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_NAME        "Large Tick Size 1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_DESCRIPTION "largeTickSize1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_FILTER      "deribit.marketdataapi.largeticksize1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_SIZE        8

static unsigned
parse_deribit_marketdataapi_large_tick_size_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_large_tick_size_1, tvb, offset, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_SIZE, DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_SIZE;
}

/* Large Tick Threshold 0 */
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_NAME        "Large Tick Threshold 0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_DESCRIPTION "largeTickThreshold0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_FILTER      "deribit.marketdataapi.largetickthreshold0"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_SIZE        8

static unsigned
parse_deribit_marketdataapi_large_tick_threshold_0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_large_tick_threshold_0, tvb, offset, DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_SIZE, DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_SIZE;
}

/* Large Tick Threshold 1 */
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_NAME        "Large Tick Threshold 1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_DESCRIPTION "largeTickThreshold1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_FILTER      "deribit.marketdataapi.largetickthreshold1"
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_SIZE        8

static unsigned
parse_deribit_marketdataapi_large_tick_threshold_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_large_tick_threshold_1, tvb, offset, DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_SIZE, DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_SIZE;
}

/* Leg Instrument Id */
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_NAME        "Leg Instrument Id"
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_DESCRIPTION "legInstrumentId"
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_FIX         2008
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_FILTER      "deribit.marketdataapi.leginstrumentid"
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_leg_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_leg_instrument_id, tvb, offset, DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_SIZE, DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_SIZE;
}

/* Maker Order Id */
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_NAME        "Maker Order Id"
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_DESCRIPTION "makerOrderId"
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_FILTER      "deribit.marketdataapi.makerorderid"
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_maker_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_maker_order_id, tvb, offset, DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_SIZE, DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_SIZE;
}

/* Mark Price */
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_NAME        "Mark Price"
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_DESCRIPTION "markPrice"
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_FILTER      "deribit.marketdataapi.markprice"
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MARK_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_mark_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_mark_price, tvb, offset, DERIBIT_MARKETDATAAPI_MARK_PRICE_SIZE, DERIBIT_MARKETDATAAPI_MARK_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MARK_PRICE_SIZE;
}

/* Match Id */
#define DERIBIT_MARKETDATAAPI_MATCH_ID_NAME        "Match Id"
#define DERIBIT_MARKETDATAAPI_MATCH_ID_DESCRIPTION "matchId"
#define DERIBIT_MARKETDATAAPI_MATCH_ID_FILTER      "deribit.marketdataapi.matchid"
#define DERIBIT_MARKETDATAAPI_MATCH_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MATCH_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_MATCH_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MATCH_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MATCH_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_match_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_match_id, tvb, offset, DERIBIT_MARKETDATAAPI_MATCH_ID_SIZE, DERIBIT_MARKETDATAAPI_MATCH_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MATCH_ID_SIZE;
}

/* Max Buy Price */
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_NAME        "Max Buy Price"
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_DESCRIPTION "maxBuyPrice"
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_FILTER      "deribit.marketdataapi.maxbuyprice"
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_max_buy_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_max_buy_price, tvb, offset, DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_SIZE, DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_SIZE;
}

/* Message Count values the dispatch switches on */
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_EMPTY_PACKET 0

/* Message Count */
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_NAME        "Message Count"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_DESCRIPTION "Count of messages contained within the packet"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_FILTER      "deribit.marketdataapi.messagecount"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SIZE        2

static unsigned
parse_deribit_marketdataapi_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_message_count, tvb, offset, DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SIZE, DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SIZE;
}

/* Message Count Short */
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_NAME        "Message Count Short"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_DESCRIPTION "messageCount"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_FILTER      "deribit.marketdataapi.messagecountshort"
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_TYPE        FT_UINT8
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_SIZE        1

static unsigned
parse_deribit_marketdataapi_message_count_short(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_message_count_short, tvb, offset, DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_SIZE, DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_SIZE;
}

/* Message Length */
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_NAME        "Message Length"
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_DESCRIPTION "Length of the message including this header"
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_FILTER      "deribit.marketdataapi.messagelength"
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_deribit_marketdataapi_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_message_length, tvb, offset, DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_SIZE, DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_SIZE;
}

/* Min Order Quantity */
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_NAME        "Min Order Quantity"
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_DESCRIPTION "minOrderQuantity"
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_FILTER      "deribit.marketdataapi.minorderquantity"
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_SIZE        8

static unsigned
parse_deribit_marketdataapi_min_order_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_min_order_quantity, tvb, offset, DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_SIZE, DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_SIZE;
}

/* Min Sell Price */
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_NAME        "Min Sell Price"
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_DESCRIPTION "minSellPrice"
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_FILTER      "deribit.marketdataapi.minsellprice"
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_min_sell_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_min_sell_price, tvb, offset, DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_SIZE, DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_SIZE;
}

/* Month */
#define DERIBIT_MARKETDATAAPI_MONTH_NAME     "Month"
#define DERIBIT_MARKETDATAAPI_MONTH_FILTER   "deribit.marketdataapi.month"
#define DERIBIT_MARKETDATAAPI_MONTH_TYPE     FT_INT16
#define DERIBIT_MARKETDATAAPI_MONTH_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_MONTH_MASK     0x0
#define DERIBIT_MARKETDATAAPI_MONTH_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MONTH_SIZE     2

static unsigned
parse_deribit_marketdataapi_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_month, tvb, offset, DERIBIT_MARKETDATAAPI_MONTH_SIZE, DERIBIT_MARKETDATAAPI_MONTH_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MONTH_SIZE;
}

/* Name */
#define DERIBIT_MARKETDATAAPI_NAME_NAME     "Name"
#define DERIBIT_MARKETDATAAPI_NAME_FILTER   "deribit.marketdataapi.name"
#define DERIBIT_MARKETDATAAPI_NAME_TYPE     FT_STRING
#define DERIBIT_MARKETDATAAPI_NAME_DISPLAY  BASE_NONE
#define DERIBIT_MARKETDATAAPI_NAME_MASK     0x0
#define DERIBIT_MARKETDATAAPI_NAME_ENCODING ENC_ASCII
#define DERIBIT_MARKETDATAAPI_NAME_SIZE     128

static unsigned
parse_deribit_marketdataapi_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_name, tvb, offset, DERIBIT_MARKETDATAAPI_NAME_SIZE, DERIBIT_MARKETDATAAPI_NAME_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_NAME_SIZE;
}

/* Num In Group */
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_NAME        "Num In Group"
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_DESCRIPTION "numInGroup"
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_FILTER      "deribit.marketdataapi.numingroup"
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_MASK        0x0
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_SIZE        2

static unsigned
parse_deribit_marketdataapi_num_in_group(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_num_in_group, tvb, offset, DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_SIZE, DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_SIZE;
}

/* Number Of Legs */
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_NAME        "Number Of Legs"
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_DESCRIPTION "numberOfLegs"
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_FILTER      "deribit.marketdataapi.numberoflegs"
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_SIZE        2

static unsigned
parse_deribit_marketdataapi_number_of_legs(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_number_of_legs, tvb, offset, DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_SIZE, DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_SIZE;
}

/* Order Id */
#define DERIBIT_MARKETDATAAPI_ORDER_ID_NAME        "Order Id"
#define DERIBIT_MARKETDATAAPI_ORDER_ID_DESCRIPTION "orderId"
#define DERIBIT_MARKETDATAAPI_ORDER_ID_FILTER      "deribit.marketdataapi.orderid"
#define DERIBIT_MARKETDATAAPI_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_ORDER_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_ORDER_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_order_id, tvb, offset, DERIBIT_MARKETDATAAPI_ORDER_ID_SIZE, DERIBIT_MARKETDATAAPI_ORDER_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_ORDER_ID_SIZE;
}

/* Padding */
#define DERIBIT_MARKETDATAAPI_PADDING_NAME        "Padding"
#define DERIBIT_MARKETDATAAPI_PADDING_DESCRIPTION "Alignment padding out to the message length"
#define DERIBIT_MARKETDATAAPI_PADDING_FILTER      "deribit.marketdataapi.padding"
#define DERIBIT_MARKETDATAAPI_PADDING_TYPE        FT_BYTES
#define DERIBIT_MARKETDATAAPI_PADDING_DISPLAY     BASE_NONE
#define DERIBIT_MARKETDATAAPI_PADDING_MASK        0x0
#define DERIBIT_MARKETDATAAPI_PADDING_ENCODING    ENC_NA

/* Price */
#define DERIBIT_MARKETDATAAPI_PRICE_NAME     "Price"
#define DERIBIT_MARKETDATAAPI_PRICE_FILTER   "deribit.marketdataapi.price"
#define DERIBIT_MARKETDATAAPI_PRICE_TYPE     FT_INT64
#define DERIBIT_MARKETDATAAPI_PRICE_DISPLAY  BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_PRICE_MASK     0x0
#define DERIBIT_MARKETDATAAPI_PRICE_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_PRICE_SIZE     8

static unsigned
parse_deribit_marketdataapi_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_price, tvb, offset, DERIBIT_MARKETDATAAPI_PRICE_SIZE, DERIBIT_MARKETDATAAPI_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_PRICE_SIZE;
}

/* Price Asset */
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_NAME        "Price Asset"
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_DESCRIPTION "priceAsset"
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_FILTER      "deribit.marketdataapi.priceasset"
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_TYPE        FT_STRING
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_DISPLAY     BASE_NONE
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_MASK        0x0
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_ENCODING    ENC_ASCII
#define DERIBIT_MARKETDATAAPI_PRICE_ASSET_SIZE        8

static unsigned
parse_deribit_marketdataapi_price_asset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_price_asset, tvb, offset, DERIBIT_MARKETDATAAPI_PRICE_ASSET_SIZE, DERIBIT_MARKETDATAAPI_PRICE_ASSET_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_PRICE_ASSET_SIZE;
}

/* Quantity Asset */
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_NAME        "Quantity Asset"
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_DESCRIPTION "quantityAsset"
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_FILTER      "deribit.marketdataapi.quantityasset"
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_TYPE        FT_STRING
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_DISPLAY     BASE_NONE
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_MASK        0x0
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_ENCODING    ENC_ASCII
#define DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_SIZE        8

static unsigned
parse_deribit_marketdataapi_quantity_asset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_quantity_asset, tvb, offset, DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_SIZE, DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_SIZE;
}

/* Quantity Exponent */
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_NAME        "Quantity Exponent"
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_DESCRIPTION "quantityExponent"
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_FILTER      "deribit.marketdataapi.quantityexponent"
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_TYPE        FT_INT8
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_SIZE        1

static unsigned
parse_deribit_marketdataapi_quantity_exponent(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_quantity_exponent, tvb, offset, DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_SIZE, DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_SIZE;
}

/* Quantity Mantissa */
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_NAME        "Quantity Mantissa"
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_DESCRIPTION "quantityMantissa"
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_FILTER      "deribit.marketdataapi.quantitymantissa"
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_MASK        0x0
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_SIZE        8

static unsigned
parse_deribit_marketdataapi_quantity_mantissa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_quantity_mantissa, tvb, offset, DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_SIZE, DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_SIZE;
}

/* Quote Currency */
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_NAME        "Quote Currency"
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_DESCRIPTION "quoteCurrency"
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_FILTER      "deribit.marketdataapi.quotecurrency"
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_TYPE        FT_STRING
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_DISPLAY     BASE_NONE
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_MASK        0x0
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_ENCODING    ENC_ASCII
#define DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_SIZE        8

static unsigned
parse_deribit_marketdataapi_quote_currency(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_quote_currency, tvb, offset, DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_SIZE, DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_SIZE;
}

/* Ratio */
#define DERIBIT_MARKETDATAAPI_RATIO_NAME     "Ratio"
#define DERIBIT_MARKETDATAAPI_RATIO_FIX      2009
#define DERIBIT_MARKETDATAAPI_RATIO_FILTER   "deribit.marketdataapi.ratio"
#define DERIBIT_MARKETDATAAPI_RATIO_TYPE     FT_INT8
#define DERIBIT_MARKETDATAAPI_RATIO_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_RATIO_MASK     0x0
#define DERIBIT_MARKETDATAAPI_RATIO_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_RATIO_SIZE     1

static unsigned
parse_deribit_marketdataapi_ratio(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_ratio, tvb, offset, DERIBIT_MARKETDATAAPI_RATIO_SIZE, DERIBIT_MARKETDATAAPI_RATIO_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_RATIO_SIZE;
}

/* Reason */
#define DERIBIT_MARKETDATAAPI_REASON_NAME     "Reason"
#define DERIBIT_MARKETDATAAPI_REASON_FILTER   "deribit.marketdataapi.reason"
#define DERIBIT_MARKETDATAAPI_REASON_TYPE     FT_INT8
#define DERIBIT_MARKETDATAAPI_REASON_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_REASON_MASK     0x0
#define DERIBIT_MARKETDATAAPI_REASON_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_REASON_SIZE     1

static const value_string deribit_marketdataapi_reason_vals[] = {
    { 1, "Seq Too Low" },
    { 2, "Seq Too High" },
    { 3, "Rate Limit Exceeded" },
    { 4, "Other Error" },
    { 0, NULL }
};

static unsigned
parse_deribit_marketdataapi_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_reason, tvb, offset, DERIBIT_MARKETDATAAPI_REASON_SIZE, DERIBIT_MARKETDATAAPI_REASON_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_REASON_SIZE;
}

/* Reserved 29 */
#define DERIBIT_MARKETDATAAPI_RESERVED_29_NAME        "Reserved 29"
#define DERIBIT_MARKETDATAAPI_RESERVED_29_DESCRIPTION "29 reserved bits"
#define DERIBIT_MARKETDATAAPI_RESERVED_29_FILTER      "deribit.marketdataapi.reserved29"
#define DERIBIT_MARKETDATAAPI_RESERVED_29_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_RESERVED_29_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_RESERVED_29_MASK        0xFFFFFFF8

/* Reserved 30 */
#define DERIBIT_MARKETDATAAPI_RESERVED_30_NAME        "Reserved 30"
#define DERIBIT_MARKETDATAAPI_RESERVED_30_DESCRIPTION "30 reserved bits"
#define DERIBIT_MARKETDATAAPI_RESERVED_30_FILTER      "deribit.marketdataapi.reserved30"
#define DERIBIT_MARKETDATAAPI_RESERVED_30_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_RESERVED_30_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_RESERVED_30_MASK        0xFFFFFFFC

/* Reserved 5 */
#define DERIBIT_MARKETDATAAPI_RESERVED_5_NAME        "Reserved 5"
#define DERIBIT_MARKETDATAAPI_RESERVED_5_DESCRIPTION "5 reserved bits"
#define DERIBIT_MARKETDATAAPI_RESERVED_5_FILTER      "deribit.marketdataapi.reserved5"
#define DERIBIT_MARKETDATAAPI_RESERVED_5_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_RESERVED_5_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_RESERVED_5_MASK        0xF8

/* Retransmit */
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_NAME        "Retransmit"
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_DESCRIPTION "Retransmit packet indicator (Bit 2)"
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_FILTER      "deribit.marketdataapi.retransmit"
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_RETRANSMIT_MASK        0x04

/* Retry Delay Nanos */
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_NAME        "Retry Delay Nanos"
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_DESCRIPTION "retryDelayNanos"
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_FILTER      "deribit.marketdataapi.retrydelaynanos"
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE        8

static unsigned
parse_deribit_marketdataapi_retry_delay_nanos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_retry_delay_nanos, tvb, offset, DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE, DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE;
}

/* Schema Version */
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_NAME     "Schema Version"
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_FILTER   "deribit.marketdataapi.schemaversion"
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_TYPE     FT_UINT16
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_MASK     0x0
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_SIZE     2

static unsigned
parse_deribit_marketdataapi_schema_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_schema_version, tvb, offset, DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_SIZE, DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_SIZE;
}

/* Sending Time */
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_NAME        "Sending Time"
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_DESCRIPTION "UTC timestamp of when the packet was sent, nanoseconds since Unix epoch (January 1st, 1970, 00:00:00 GMT)"
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_FILTER      "deribit.marketdataapi.sendingtime"
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_MASK        0x0
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_SENDING_TIME_SIZE        8

static unsigned
parse_deribit_marketdataapi_sending_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_sending_time, tvb, offset, DERIBIT_MARKETDATAAPI_SENDING_TIME_SIZE, DERIBIT_MARKETDATAAPI_SENDING_TIME_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SENDING_TIME_SIZE;
}

/* Seq Num */
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_NAME        "Seq Num"
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_DESCRIPTION "Sequence number of the first message in the packet"
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_FILTER      "deribit.marketdataapi.seqnum"
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_MASK        0x0
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_SEQ_NUM_SIZE        8

static unsigned
parse_deribit_marketdataapi_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_seq_num, tvb, offset, DERIBIT_MARKETDATAAPI_SEQ_NUM_SIZE, DERIBIT_MARKETDATAAPI_SEQ_NUM_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SEQ_NUM_SIZE;
}

/* Settlement Price */
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_NAME        "Settlement Price"
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_DESCRIPTION "settlementPrice"
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_FILTER      "deribit.marketdataapi.settlementprice"
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_settlement_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_settlement_price, tvb, offset, DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE, DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE;
}

/* Snapshot */
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_NAME        "Snapshot"
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_DESCRIPTION "Snapshot packet indicator (Bit 1)"
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_FILTER      "deribit.marketdataapi.snapshot"
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_SNAPSHOT_MASK        0x02

/* Sort Order Id */
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_NAME        "Sort Order Id"
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_DESCRIPTION "sortOrderId"
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_FILTER      "deribit.marketdataapi.sortorderid"
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_sort_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_sort_order_id, tvb, offset, DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_SIZE, DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_SIZE;
}

/* Start Of Transaction */
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_NAME        "Start Of Transaction"
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_DESCRIPTION "Start of transaction indicator"
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_FILTER      "deribit.marketdataapi.startoftransaction"
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_TYPE        FT_BOOLEAN
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_DISPLAY     8
#define DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_MASK        0x01

/* Status */
#define DERIBIT_MARKETDATAAPI_STATUS_NAME     "Status"
#define DERIBIT_MARKETDATAAPI_STATUS_FILTER   "deribit.marketdataapi.status"
#define DERIBIT_MARKETDATAAPI_STATUS_TYPE     FT_INT8
#define DERIBIT_MARKETDATAAPI_STATUS_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_STATUS_MASK     0x0
#define DERIBIT_MARKETDATAAPI_STATUS_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_STATUS_SIZE     1

static const value_string deribit_marketdataapi_status_vals[] = {
    { 0, "Open" },
    { 1, "Inactive" },
    { 2, "Settlement" },
    { 3, "Delivered" },
    { 4, "Locked" },
    { 5, "Halted" },
    { 0, NULL }
};

static unsigned
parse_deribit_marketdataapi_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_status, tvb, offset, DERIBIT_MARKETDATAAPI_STATUS_SIZE, DERIBIT_MARKETDATAAPI_STATUS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_STATUS_SIZE;
}

/* Strike Price */
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_NAME        "Strike Price"
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_DESCRIPTION "strikePrice"
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_FILTER      "deribit.marketdataapi.strikeprice"
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_STRIKE_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_strike_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_strike_price, tvb, offset, DERIBIT_MARKETDATAAPI_STRIKE_PRICE_SIZE, DERIBIT_MARKETDATAAPI_STRIKE_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_STRIKE_PRICE_SIZE;
}

/* Symbol */
#define DERIBIT_MARKETDATAAPI_SYMBOL_NAME     "Symbol"
#define DERIBIT_MARKETDATAAPI_SYMBOL_FILTER   "deribit.marketdataapi.symbol"
#define DERIBIT_MARKETDATAAPI_SYMBOL_TYPE     FT_STRING
#define DERIBIT_MARKETDATAAPI_SYMBOL_DISPLAY  BASE_NONE
#define DERIBIT_MARKETDATAAPI_SYMBOL_MASK     0x0
#define DERIBIT_MARKETDATAAPI_SYMBOL_ENCODING ENC_ASCII
#define DERIBIT_MARKETDATAAPI_SYMBOL_SIZE     64

static unsigned
parse_deribit_marketdataapi_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_symbol, tvb, offset, DERIBIT_MARKETDATAAPI_SYMBOL_SIZE, DERIBIT_MARKETDATAAPI_SYMBOL_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_SYMBOL_SIZE;
}

/* Taker Order Id */
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_NAME        "Taker Order Id"
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_DESCRIPTION "takerOrderId"
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_FILTER      "deribit.marketdataapi.takerorderid"
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_SIZE        8

static unsigned
parse_deribit_marketdataapi_taker_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_taker_order_id, tvb, offset, DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_SIZE, DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_SIZE;
}

/* Template Id values the dispatch switches on */
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION    10
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INDEX_DEFINITION         11
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14       14
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_REF           15
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_STATUS_UPDATE 16
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT                  20
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT                  21
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED          22
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED          23
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE               24
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE               25
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY            30
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE                    31
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE              33
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER          100
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER         101
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE             119
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST       200
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT        202
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE    12
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_13       13

/* Template Id */
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_NAME        "Template Id"
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_DESCRIPTION "Template ID used to encode the message"
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_FILTER      "deribit.marketdataapi.templateid"
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SIZE        2

static const value_string deribit_marketdataapi_template_id_vals[] = {
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION, "Instrument Definition Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INDEX_DEFINITION, "Index Definition Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14, "Instrument Info Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_REF, "Instrument Ref Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_STATUS_UPDATE, "Instrument Status Update Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT, "Bid Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT, "Ask Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED, "Bid Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED, "Ask Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE, "Bid Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE, "Ask Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE, "Block Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER, "Snapshot Header Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER, "Snapshot Trailer Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_13, "Instrument Info Message" },
    { 0, NULL }
};

static unsigned
parse_deribit_marketdataapi_template_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_template_id, tvb, offset, DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SIZE, DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SIZE;
}

/* Threshold Price */
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_NAME        "Threshold Price"
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_DESCRIPTION "thresholdPrice"
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_FIX         1016
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_FILTER      "deribit.marketdataapi.thresholdprice"
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_SIZE        8

static unsigned
parse_deribit_marketdataapi_threshold_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_threshold_price, tvb, offset, DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_SIZE, DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_SIZE;
}

/* Tick Size */
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_NAME        "Tick Size"
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_DESCRIPTION "tickSize"
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_FILTER      "deribit.marketdataapi.ticksize"
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_DISPLAY     BASE_CUSTOM
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TICK_SIZE_SIZE        8

static unsigned
parse_deribit_marketdataapi_tick_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_tick_size, tvb, offset, DERIBIT_MARKETDATAAPI_TICK_SIZE_SIZE, DERIBIT_MARKETDATAAPI_TICK_SIZE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TICK_SIZE_SIZE;
}

/* Timestamp */
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_NAME     "Timestamp"
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_FILTER   "deribit.marketdataapi.timestamp"
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_TYPE     FT_INT64
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_MASK     0x0
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TIMESTAMP_SIZE     8

static unsigned
parse_deribit_marketdataapi_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_timestamp, tvb, offset, DERIBIT_MARKETDATAAPI_TIMESTAMP_SIZE, DERIBIT_MARKETDATAAPI_TIMESTAMP_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TIMESTAMP_SIZE;
}

/* Total Filled Mantissa */
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_NAME        "Total Filled Mantissa"
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_DESCRIPTION "totalFilledMantissa"
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_FILTER      "deribit.marketdataapi.totalfilledmantissa"
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_TYPE        FT_INT64
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_SIZE        8

static unsigned
parse_deribit_marketdataapi_total_filled_mantissa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_total_filled_mantissa, tvb, offset, DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_SIZE, DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_SIZE;
}

/* Trade Count */
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_NAME        "Trade Count"
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_DESCRIPTION "tradeCount"
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_FILTER      "deribit.marketdataapi.tradecount"
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_TYPE        FT_INT32
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TRADE_COUNT_SIZE        4

static unsigned
parse_deribit_marketdataapi_trade_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_trade_count, tvb, offset, DERIBIT_MARKETDATAAPI_TRADE_COUNT_SIZE, DERIBIT_MARKETDATAAPI_TRADE_COUNT_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TRADE_COUNT_SIZE;
}

/* Trading Status */
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_NAME        "Trading Status"
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_DESCRIPTION "tradingStatus"
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_FILTER      "deribit.marketdataapi.tradingstatus"
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_TYPE        FT_INT8
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TRADING_STATUS_SIZE        1

static const value_string deribit_marketdataapi_trading_status_vals[] = {
    { 0, "Open" },
    { 1, "Inactive" },
    { 2, "Settlement" },
    { 3, "Delivered" },
    { 4, "Locked" },
    { 5, "Halted" },
    { 0, NULL }
};

static unsigned
parse_deribit_marketdataapi_trading_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_trading_status, tvb, offset, DERIBIT_MARKETDATAAPI_TRADING_STATUS_SIZE, DERIBIT_MARKETDATAAPI_TRADING_STATUS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TRADING_STATUS_SIZE;
}

/* Transact Time */
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_NAME        "Transact Time"
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_DESCRIPTION "UTC timestamp of when the transaction occurred, nanoseconds since Unix epoch (January 1st, 1970, 00:00:00 GMT)"
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_FILTER      "deribit.marketdataapi.transacttime"
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TRANSACT_TIME_SIZE        8

static unsigned
parse_deribit_marketdataapi_transact_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    if ((int64_t)tvb_get_letoh64(tvb, offset) == 0) {
        nstime_t empty = NSTIME_INIT_ZERO;

        proto_tree_add_time_format_value(tree, hf_deribit_marketdataapi_transact_time, tvb, offset, DERIBIT_MARKETDATAAPI_TRANSACT_TIME_SIZE, &empty, "No Value");
    }
    else {
        proto_tree_add_item(tree, hf_deribit_marketdataapi_transact_time, tvb, offset, DERIBIT_MARKETDATAAPI_TRANSACT_TIME_SIZE, DERIBIT_MARKETDATAAPI_TRANSACT_TIME_ENCODING);
    }

    return offset + DERIBIT_MARKETDATAAPI_TRANSACT_TIME_SIZE;
}

/* Type */
#define DERIBIT_MARKETDATAAPI_TYPE_NAME     "Type"
#define DERIBIT_MARKETDATAAPI_TYPE_FILTER   "deribit.marketdataapi.type"
#define DERIBIT_MARKETDATAAPI_TYPE_TYPE     FT_INT8
#define DERIBIT_MARKETDATAAPI_TYPE_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_TYPE_MASK     0x0
#define DERIBIT_MARKETDATAAPI_TYPE_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TYPE_SIZE     1

static const value_string deribit_marketdataapi_type_vals[] = {
    { 0, "Perp Future" },
    { 1, "Option" },
    { 2, "Spot" },
    { 3, "Future Combo" },
    { 4, "Option Combo" },
    { 5, "Dated Future" },
    { 0, NULL }
};

static unsigned
parse_deribit_marketdataapi_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_type, tvb, offset, DERIBIT_MARKETDATAAPI_TYPE_SIZE, DERIBIT_MARKETDATAAPI_TYPE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TYPE_SIZE;
}

/* Underlying */
#define DERIBIT_MARKETDATAAPI_UNDERLYING_NAME     "Underlying"
#define DERIBIT_MARKETDATAAPI_UNDERLYING_FILTER   "deribit.marketdataapi.underlying"
#define DERIBIT_MARKETDATAAPI_UNDERLYING_TYPE     FT_STRING
#define DERIBIT_MARKETDATAAPI_UNDERLYING_DISPLAY  BASE_NONE
#define DERIBIT_MARKETDATAAPI_UNDERLYING_MASK     0x0
#define DERIBIT_MARKETDATAAPI_UNDERLYING_ENCODING ENC_ASCII
#define DERIBIT_MARKETDATAAPI_UNDERLYING_SIZE     64

static unsigned
parse_deribit_marketdataapi_underlying(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_underlying, tvb, offset, DERIBIT_MARKETDATAAPI_UNDERLYING_SIZE, DERIBIT_MARKETDATAAPI_UNDERLYING_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_UNDERLYING_SIZE;
}

/* Week Of Month */
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_NAME        "Week Of Month"
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_DESCRIPTION "weekOfMonth"
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_FILTER      "deribit.marketdataapi.weekofmonth"
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_TYPE        FT_INT16
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_DISPLAY     BASE_DEC
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_MASK        0x0
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_SIZE        2

static unsigned
parse_deribit_marketdataapi_week_of_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_week_of_month, tvb, offset, DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_SIZE, DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_SIZE;
}

/* Year */
#define DERIBIT_MARKETDATAAPI_YEAR_NAME     "Year"
#define DERIBIT_MARKETDATAAPI_YEAR_FILTER   "deribit.marketdataapi.year"
#define DERIBIT_MARKETDATAAPI_YEAR_TYPE     FT_INT16
#define DERIBIT_MARKETDATAAPI_YEAR_DISPLAY  BASE_DEC
#define DERIBIT_MARKETDATAAPI_YEAR_MASK     0x0
#define DERIBIT_MARKETDATAAPI_YEAR_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_YEAR_SIZE     2

static unsigned
parse_deribit_marketdataapi_year(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_marketdataapi_year, tvb, offset, DERIBIT_MARKETDATAAPI_YEAR_SIZE, DERIBIT_MARKETDATAAPI_YEAR_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_YEAR_SIZE;
}

/*
 * Deribit MarketDataApi Structs
 */

/* Packet Type */
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_NAME        "Packet Type"
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_DESCRIPTION "Uint16 bit set carrying the packet type (INCREMENTAL_UPDATE / SNAPSHOT / RETRANSMIT)"
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_FILTER      "deribit.marketdataapi.packettype"
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_MASK        0x0
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_PACKET_TYPE_SIZE        2

static int * const deribit_marketdataapi_packet_type_fields[] = {
    &hf_deribit_marketdataapi_retransmit,
    &hf_deribit_marketdataapi_snapshot,
    &hf_deribit_marketdataapi_incremental_update,
    NULL
};

static unsigned
parse_deribit_marketdataapi_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_packet_type,
        ett_deribit_marketdataapi_packet_type, deribit_marketdataapi_packet_type_fields, DERIBIT_MARKETDATAAPI_PACKET_TYPE_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_PACKET_TYPE_SIZE;
}

/* Message Flags */
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_NAME        "Message Flags"
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_DESCRIPTION "Uint16 bit set carrying transaction boundary indicators"
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_FILTER      "deribit.marketdataapi.messageflags"
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_TYPE        FT_UINT16
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_SIZE        2

static int * const deribit_marketdataapi_message_flags_fields[] = {
    &hf_deribit_marketdataapi_end_of_transaction,
    &hf_deribit_marketdataapi_start_of_transaction,
    NULL
};

static unsigned
parse_deribit_marketdataapi_message_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_message_flags,
        ett_deribit_marketdataapi_message_flags, deribit_marketdataapi_message_flags_fields, DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_SIZE;
}

/* Flags */
#define DERIBIT_MARKETDATAAPI_FLAGS_NAME        "Flags"
#define DERIBIT_MARKETDATAAPI_FLAGS_DESCRIPTION "InstrumentFlags bit set"
#define DERIBIT_MARKETDATAAPI_FLAGS_FILTER      "deribit.marketdataapi.flags"
#define DERIBIT_MARKETDATAAPI_FLAGS_TYPE        FT_UINT8
#define DERIBIT_MARKETDATAAPI_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_FLAGS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_FLAGS_SIZE        1

static int * const deribit_marketdataapi_flags_fields[] = {
    &hf_deribit_marketdataapi_reserved_5,
    &hf_deribit_marketdataapi_is_perpetual,
    &hf_deribit_marketdataapi_is_put_option,
    &hf_deribit_marketdataapi_is_reversed,
    NULL
};

static unsigned
parse_deribit_marketdataapi_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_flags,
        ett_deribit_marketdataapi_flags, deribit_marketdataapi_flags_fields, DERIBIT_MARKETDATAAPI_FLAGS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_FLAGS_SIZE;
}

/* Taker Flags */
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_NAME        "Taker Flags"
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_DESCRIPTION "TradeFlags bit set"
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_FILTER      "deribit.marketdataapi.takerflags"
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_TYPE        FT_UINT32
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_TAKER_FLAGS_SIZE        4

static int * const deribit_marketdataapi_taker_flags_fields[] = {
    &hf_deribit_marketdataapi_reserved_30,
    &hf_deribit_marketdataapi_is_liquidation,
    &hf_deribit_marketdataapi_is_sell,
    NULL
};

static unsigned
parse_deribit_marketdataapi_taker_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_taker_flags,
        ett_deribit_marketdataapi_taker_flags, deribit_marketdataapi_taker_flags_fields, DERIBIT_MARKETDATAAPI_TAKER_FLAGS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_TAKER_FLAGS_SIZE;
}

/* Maker Flags */
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_NAME        "Maker Flags"
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_DESCRIPTION "TradeFlags bit set"
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_FILTER      "deribit.marketdataapi.makerflags"
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_TYPE        FT_UINT32
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_MASK        0x0
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_MAKER_FLAGS_SIZE        4

static int * const deribit_marketdataapi_maker_flags_fields[] = {
    &hf_deribit_marketdataapi_reserved_30,
    &hf_deribit_marketdataapi_is_liquidation,
    &hf_deribit_marketdataapi_is_sell,
    NULL
};

static unsigned
parse_deribit_marketdataapi_maker_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_maker_flags,
        ett_deribit_marketdataapi_maker_flags, deribit_marketdataapi_maker_flags_fields, DERIBIT_MARKETDATAAPI_MAKER_FLAGS_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_MAKER_FLAGS_SIZE;
}

/* Flags */
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_NAME        "Flags"
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_DESCRIPTION "InstrumentFlags bit set"
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_FILTER      "deribit.marketdataapi.flags"
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_TYPE        FT_UINT32
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_DISPLAY     BASE_HEX
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_MASK        0x0
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_MARKETDATAAPI_FLAGS_V01_SIZE        4

static int * const deribit_marketdataapi_flags_v01_fields[] = {
    &hf_deribit_marketdataapi_reserved_29,
    &hf_deribit_marketdataapi_is_perpetual,
    &hf_deribit_marketdataapi_is_put_option,
    &hf_deribit_marketdataapi_is_reversed,
    NULL
};

static unsigned
parse_deribit_marketdataapi_flags_v01(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_marketdataapi_flags_v01,
        ett_deribit_marketdataapi_flags_v01, deribit_marketdataapi_flags_v01_fields, DERIBIT_MARKETDATAAPI_FLAGS_V01_ENCODING);

    return offset + DERIBIT_MARKETDATAAPI_FLAGS_V01_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_deribit_marketdataapi_md_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_group_size_encoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_marketdataapi_instrument_definition_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_definition_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_marketdataapi_index_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_ref(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_bid_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_ask_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_bid_qty_reduced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_ask_qty_reduced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_bid_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_ask_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_trade_summary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_block_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_snapshot_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_snapshot_trailer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_end_of_cycle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_retransmit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_retransmit_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_instrument(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_logical_expiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_trading_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_bid_put_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_ask_put_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_trade_summary_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_marketdataapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_deribit_marketdataapi_payload_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);

/* Md Message Header */
static unsigned
dissect_deribit_marketdataapi_md_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_md_message_header, &item, "Md Message Header");
    }

    unsigned start = offset;

    offset = parse_deribit_marketdataapi_message_length(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_template_id(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_schema_version(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_message_flags(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_transact_time(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Instrument Definition Message */
static unsigned
dissect_deribit_marketdataapi_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_name(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_index_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_underlying(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_asset(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_price_asset(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_expiry_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_min_order_quantity(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_exponent(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_type(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_flags(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_status(tvb, pinfo, tree, offset);
    offset = dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_marketdataapi_instrument_definition_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Definition Message large Tick Sizes Groups */
static unsigned
dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups, &item, "Instrument Definition Message large Tick Sizes Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_marketdataapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Instrument Definition Message large Tick Sizes Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Group Size Encoding */
static unsigned
dissect_deribit_marketdataapi_group_size_encoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_group_size_encoding, &item, "Group Size Encoding");
    }

    unsigned start = offset;

    offset = parse_deribit_marketdataapi_block_length(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_num_in_group(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Instrument Definition Message large Tick Sizes Group */
static unsigned
dissect_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = deribit_marketdataapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group, &item, "Instrument Definition Message large Tick Sizes Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group, &item, "Instrument Definition Message large Tick Sizes Group");
    }

    unsigned start = offset;

    offset = parse_deribit_marketdataapi_large_tick_size(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_threshold_price(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Instrument Definition Message legs Groups */
static unsigned
dissect_deribit_marketdataapi_instrument_definition_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_legs_groups, &item, "Instrument Definition Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_marketdataapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Instrument Definition Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_marketdataapi_instrument_definition_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Instrument Definition Message legs Group */
static unsigned
dissect_deribit_marketdataapi_instrument_definition_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = deribit_marketdataapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_legs_group, &item, "Instrument Definition Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_instrument_definition_message_legs_group, &item, "Instrument Definition Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_marketdataapi_leg_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_ratio(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Index Definition Message */
static unsigned
dissect_deribit_marketdataapi_index_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_index_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_name(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Info Message */
static unsigned
dissect_deribit_marketdataapi_instrument_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_min_sell_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_max_buy_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_index_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_mark_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Ref Message */
static unsigned
dissect_deribit_marketdataapi_instrument_ref(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_current_funding(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_funding_8h(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_estimated_delivery_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_delivery_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_settlement_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Status Update Message */
static unsigned
dissect_deribit_marketdataapi_instrument_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_trading_status(tvb, pinfo, tree, offset);

    return offset;
}

/* Bid Put Message */
static unsigned
dissect_deribit_marketdataapi_bid_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_sort_order_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Ask Put Message */
static unsigned
dissect_deribit_marketdataapi_ask_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_sort_order_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Bid Qty Reduced Message */
static unsigned
dissect_deribit_marketdataapi_bid_qty_reduced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);

    return offset;
}

/* Ask Qty Reduced Message */
static unsigned
dissect_deribit_marketdataapi_ask_qty_reduced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);

    return offset;
}

/* Bid Delete Message */
static unsigned
dissect_deribit_marketdataapi_bid_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Ask Delete Message */
static unsigned
dissect_deribit_marketdataapi_ask_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Summary Message */
static unsigned
dissect_deribit_marketdataapi_trade_summary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_taker_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_total_filled_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_deepest_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_mark_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_index_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_trade_count(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_taker_flags(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_deribit_marketdataapi_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_maker_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_fill_qty_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_fill_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_maker_flags(tvb, pinfo, tree, offset);

    return offset;
}

/* Block Trade Message */
static unsigned
dissect_deribit_marketdataapi_block_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_block_trade_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_block_rfq_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_fill_qty_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_fill_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_mark_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_index_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_implied_volatility(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_taker_flags(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_number_of_legs(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Header Message */
static unsigned
dissect_deribit_marketdataapi_snapshot_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_incremental_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_incremental_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* Snapshot Trailer Message */
static unsigned
dissect_deribit_marketdataapi_snapshot_trailer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_increment_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Cycle Message */
static unsigned
dissect_deribit_marketdataapi_end_of_cycle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_active_instrument_count(tvb, pinfo, tree, offset);

    return offset;
}

/* Retransmit Request Message */
static unsigned
dissect_deribit_marketdataapi_retransmit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_begin_seq_num(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_message_count_short(tvb, pinfo, tree, offset);

    return offset;
}

/* Retransmit Reject Message */
static unsigned
dissect_deribit_marketdataapi_retransmit_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_retry_delay_nanos(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_details(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Message */
static unsigned
dissect_deribit_marketdataapi_instrument(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_name(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_base_currency(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quote_currency(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_base_increment(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_large_tick_size_0(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_large_tick_threshold_0(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_large_tick_size_1(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_large_tick_threshold_1(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_creation_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_expiry_time(tvb, pinfo, tree, offset);
    offset = dissect_deribit_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_flags_v01(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_type(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_exponent(tvb, pinfo, tree, offset);

    return offset;
}

/* Logical Expiry */
static unsigned
dissect_deribit_marketdataapi_logical_expiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_marketdataapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_marketdataapi_logical_expiry, &item, "Logical Expiry");
    }

    unsigned start = offset;

    offset = parse_deribit_marketdataapi_year(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_month(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_week_of_month(tvb, pinfo, group, offset);
    offset = parse_deribit_marketdataapi_day_of_month(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Trading Status Update Message */
static unsigned
dissect_deribit_marketdataapi_trading_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_trading_status(tvb, pinfo, tree, offset);

    return offset;
}

/* Bid Put Message V01 */
static unsigned
dissect_deribit_marketdataapi_bid_put_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Ask Put Message V01 */
static unsigned
dissect_deribit_marketdataapi_ask_put_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_quantity_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Summary Message V01 */
static unsigned
dissect_deribit_marketdataapi_trade_summary_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_marketdataapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_taker_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_total_filled_mantissa(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_deepest_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_mark_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_index_price(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_implied_volatility(tvb, pinfo, tree, offset);
    offset = parse_deribit_marketdataapi_taker_flags(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * Deribit MarketDataApi Parse Trees, a dispatch per distinct branch definition
 */

static const value_string deribit_marketdataapi_messages[] = {
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION, "Instrument Definition Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INDEX_DEFINITION, "Index Definition Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14, "Instrument Info Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_REF, "Instrument Ref Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_STATUS_UPDATE, "Instrument Status Update Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT, "Bid Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT, "Ask Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED, "Bid Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED, "Ask Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE, "Bid Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE, "Ask Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE, "Block Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER, "Snapshot Header Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER, "Snapshot Trailer Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_marketdataapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    switch (template_id) {
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION:
        return dissect_deribit_marketdataapi_instrument_definition(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INDEX_DEFINITION:
        return dissect_deribit_marketdataapi_index_definition(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14:
        return dissect_deribit_marketdataapi_instrument_info(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_REF:
        return dissect_deribit_marketdataapi_instrument_ref(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_STATUS_UPDATE:
        return dissect_deribit_marketdataapi_instrument_status_update(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT:
        return dissect_deribit_marketdataapi_bid_put(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT:
        return dissect_deribit_marketdataapi_ask_put(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED:
        return dissect_deribit_marketdataapi_bid_qty_reduced(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED:
        return dissect_deribit_marketdataapi_ask_qty_reduced(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE:
        return dissect_deribit_marketdataapi_bid_delete(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE:
        return dissect_deribit_marketdataapi_ask_delete(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_deribit_marketdataapi_trade_summary(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_deribit_marketdataapi_trade(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE:
        return dissect_deribit_marketdataapi_block_trade(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER:
        return dissect_deribit_marketdataapi_snapshot_header(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER:
        return dissect_deribit_marketdataapi_snapshot_trailer(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return dissect_deribit_marketdataapi_end_of_cycle(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_deribit_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_deribit_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string deribit_marketdataapi_messages_v01[] = {
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION, "Instrument Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_13, "Instrument Info Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14, "Instrument Ref Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT, "Bid Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT, "Ask Put Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED, "Bid Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED, "Ask Qty Reduced Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE, "Bid Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE, "Ask Delete Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE, "Block Trade Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER, "Snapshot Header Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER, "Snapshot Trailer Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_marketdataapi_payload_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    switch (template_id) {
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION:
        return dissect_deribit_marketdataapi_instrument(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return dissect_deribit_marketdataapi_trading_status_update(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_13:
        return dissect_deribit_marketdataapi_instrument_info(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14:
        return dissect_deribit_marketdataapi_instrument_ref(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT:
        return dissect_deribit_marketdataapi_bid_put_v01(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT:
        return dissect_deribit_marketdataapi_ask_put_v01(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED:
        return dissect_deribit_marketdataapi_bid_qty_reduced(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED:
        return dissect_deribit_marketdataapi_ask_qty_reduced(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE:
        return dissect_deribit_marketdataapi_bid_delete(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE:
        return dissect_deribit_marketdataapi_ask_delete(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_deribit_marketdataapi_trade_summary_v01(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_deribit_marketdataapi_trade(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE:
        return dissect_deribit_marketdataapi_block_trade(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER:
        return dissect_deribit_marketdataapi_snapshot_header(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER:
        return dissect_deribit_marketdataapi_snapshot_trailer(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return dissect_deribit_marketdataapi_end_of_cycle(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_deribit_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_deribit_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
deribit_marketdataapi_show(uint32_t template_id)
{
    switch (template_id) {
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_DEFINITION:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INDEX_DEFINITION:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_14:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_REF:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_STATUS_UPDATE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_PUT:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_PUT:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_QTY_REDUCED:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_QTY_REDUCED:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BID_DELETE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_ASK_DELETE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_BLOCK_TRADE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_HEADER:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_SNAPSHOT_TRAILER:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return deribit_marketdataapi_show_application_messages;
    case DERIBIT_MARKETDATAAPI_TEMPLATE_ID_INSTRUMENT_INFO_13:
        return deribit_marketdataapi_show_application_messages;
    }

    return true;
}

typedef struct deribit_marketdataapi_parse deribit_marketdataapi_parse;

struct deribit_marketdataapi_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
};

static const deribit_marketdataapi_parse deribit_marketdataapi_parse_v10 = { deribit_marketdataapi_messages, dissect_deribit_marketdataapi_payload };
static const deribit_marketdataapi_parse deribit_marketdataapi_parse_v01 = { deribit_marketdataapi_messages_v01, dissect_deribit_marketdataapi_payload_v01 };

/* Parse tree of the selected version */
static const deribit_marketdataapi_parse *
deribit_marketdataapi_parse_for(int version)
{
    switch (version) {
    case DERIBIT_MARKETDATAAPI_VERSION_0_1:
        return &deribit_marketdataapi_parse_v01;
    default:
        return &deribit_marketdataapi_parse_v10;
    }
}

/* Packet Header */
static unsigned
dissect_deribit_marketdataapi_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, DERIBIT_MARKETDATAAPI_HEADER_SIZE,
        ett_deribit_marketdataapi_header, NULL, "Packet Header");

    offset = parse_deribit_marketdataapi_sending_time(tvb, pinfo, header, offset);
    offset = parse_deribit_marketdataapi_seq_num(tvb, pinfo, header, offset);
    offset = parse_deribit_marketdataapi_channel_id(tvb, pinfo, header, offset);
    offset = parse_deribit_marketdataapi_packet_type(tvb, pinfo, header, offset);
    offset = parse_deribit_marketdataapi_message_count(tvb, pinfo, header, offset);

    return offset;
}

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_deribit_marketdataapi_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const deribit_marketdataapi_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset);
    uint32_t template_id = tvb_get_letohs(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, template_id, parse->messages, "Unknown (%u)");

    proto_tree *message = deribit_marketdataapi_show(template_id)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length, ett_deribit_marketdataapi_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_deribit_marketdataapi_md_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, template_id);

    /* Padding: Alignment padding out to the message length */
    uint32_t padding = message_length - (uint32_t)(position - offset);

    if (padding > 0) {
        proto_tree_add_item(message, hf_deribit_marketdataapi_padding, tvb, position, padding, DERIBIT_MARKETDATAAPI_PADDING_ENCODING);
        position += padding;
    }

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length) {
        expert_add_info(pinfo, message, &ei_deribit_marketdataapi_length);
    }

    return message_length;
}

/* Counted messages, returns the position after the last message */
static unsigned
dissect_deribit_marketdataapi_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t count, const deribit_marketdataapi_parse *parse)
{
    for (uint32_t index = 0; index < count; index++) {
        offset += dissect_deribit_marketdataapi_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_deribit_marketdataapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, DERIBIT_MARKETDATAAPI_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_deribit_marketdataapi, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_deribit_marketdataapi);

    const deribit_marketdataapi_endpoint *endpoint = deribit_marketdataapi_endpoint_of(pinfo);

    uint32_t count = tvb_get_letohs(tvb, 22);
    uint64_t seconds = tvb_get_letoh64(tvb, 0) / UINT64_C(1000000000);
    int version = deribit_marketdataapi_version(seconds);

    proto_item_append_text(item, " %s", deribit_marketdataapi_version_name(version));

    if (endpoint != NULL) {
        proto_item_append_text(item, ", %s", endpoint->name);
    }

    const deribit_marketdataapi_parse *parse = deribit_marketdataapi_parse_for(version);
    unsigned position = dissect_deribit_marketdataapi_header(tvb, pinfo, packet, 0);

    if (count == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Empty Packet");
        return tvb_captured_length(tvb);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%u %s", count, count == 1 ? "Message" : "Messages");

    position = dissect_deribit_marketdataapi_messages(tvb, pinfo, packet, position, count, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define DERIBIT_MARKETDATAAPI_MINIMUM_SIZE 24

/* The frame was sent to an endpoint the feed is published on, which
   tells this feed from others sharing the encoding */
static bool
deribit_marketdataapi_heur_endpoint(packet_info *pinfo)
{
    return deribit_marketdataapi_endpoint_of(pinfo) != NULL;
}

/* Does the frame pass every test of Packet? */
static bool
deribit_marketdataapi_heur_accepts(tvbuff_t *tvb _U_, packet_info *pinfo)
{
    if (!deribit_marketdataapi_heur_endpoint(pinfo)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the published endpoint it was sent to */
static bool
dissect_deribit_marketdataapi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < DERIBIT_MARKETDATAAPI_MINIMUM_SIZE) {
        return false;
    }

    if (!deribit_marketdataapi_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_deribit_marketdataapi(tvb, pinfo, tree, data);

    return true;
}

/*
 * Deribit MarketDataApi Registration
 */

void
proto_register_deribit_marketdataapi(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_deribit_marketdataapi_active_instrument_count,
            { DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_NAME,
              DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_FILTER,
              DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_TYPE,
              DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_MASK,
              DERIBIT_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_base_currency,
            { DERIBIT_MARKETDATAAPI_BASE_CURRENCY_NAME,
              DERIBIT_MARKETDATAAPI_BASE_CURRENCY_FILTER,
              DERIBIT_MARKETDATAAPI_BASE_CURRENCY_TYPE,
              DERIBIT_MARKETDATAAPI_BASE_CURRENCY_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_BASE_CURRENCY_MASK,
              DERIBIT_MARKETDATAAPI_BASE_CURRENCY_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_base_increment,
            { DERIBIT_MARKETDATAAPI_BASE_INCREMENT_NAME,
              DERIBIT_MARKETDATAAPI_BASE_INCREMENT_FILTER,
              DERIBIT_MARKETDATAAPI_BASE_INCREMENT_TYPE,
              DERIBIT_MARKETDATAAPI_BASE_INCREMENT_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_BASE_INCREMENT_MASK,
              DERIBIT_MARKETDATAAPI_BASE_INCREMENT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_begin_seq_num,
            { DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_NAME,
              DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_FILTER,
              DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_TYPE,
              DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_MASK,
              DERIBIT_MARKETDATAAPI_BEGIN_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_block_length,
            { DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_NAME,
              DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_FILTER,
              DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_TYPE,
              DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_MASK,
              DERIBIT_MARKETDATAAPI_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_block_rfq_id,
            { DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_NAME,
              DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_FILTER,
              DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_TYPE,
              DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_MASK,
              DERIBIT_MARKETDATAAPI_BLOCK_RFQ_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_block_trade_id,
            { DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_NAME,
              DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_FILTER,
              DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_TYPE,
              DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_MASK,
              DERIBIT_MARKETDATAAPI_BLOCK_TRADE_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_channel_id,
            { DERIBIT_MARKETDATAAPI_CHANNEL_ID_NAME,
              DERIBIT_MARKETDATAAPI_CHANNEL_ID_FILTER,
              DERIBIT_MARKETDATAAPI_CHANNEL_ID_TYPE,
              DERIBIT_MARKETDATAAPI_CHANNEL_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_CHANNEL_ID_MASK,
              DERIBIT_MARKETDATAAPI_CHANNEL_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_creation_time,
            { DERIBIT_MARKETDATAAPI_CREATION_TIME_NAME,
              DERIBIT_MARKETDATAAPI_CREATION_TIME_FILTER,
              DERIBIT_MARKETDATAAPI_CREATION_TIME_TYPE,
              DERIBIT_MARKETDATAAPI_CREATION_TIME_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_CREATION_TIME_MASK,
              DERIBIT_MARKETDATAAPI_CREATION_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_current_funding,
            { DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_NAME,
              DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_FILTER,
              DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_TYPE,
              DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_MASK,
              DERIBIT_MARKETDATAAPI_CURRENT_FUNDING_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_day_of_month,
            { DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_NAME,
              DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_FILTER,
              DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_TYPE,
              DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_MASK,
              DERIBIT_MARKETDATAAPI_DAY_OF_MONTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_deepest_price,
            { DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_DEEPEST_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_delivery_price,
            { DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_DELIVERY_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_details,
            { DERIBIT_MARKETDATAAPI_DETAILS_NAME,
              DERIBIT_MARKETDATAAPI_DETAILS_FILTER,
              DERIBIT_MARKETDATAAPI_DETAILS_TYPE,
              DERIBIT_MARKETDATAAPI_DETAILS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_DETAILS_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_estimated_delivery_price,
            { DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_ESTIMATED_DELIVERY_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_expiry_time,
            { DERIBIT_MARKETDATAAPI_EXPIRY_TIME_NAME,
              DERIBIT_MARKETDATAAPI_EXPIRY_TIME_FILTER,
              DERIBIT_MARKETDATAAPI_EXPIRY_TIME_TYPE,
              DERIBIT_MARKETDATAAPI_EXPIRY_TIME_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_EXPIRY_TIME_MASK,
              DERIBIT_MARKETDATAAPI_EXPIRY_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_fill_price,
            { DERIBIT_MARKETDATAAPI_FILL_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_FILL_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_FILL_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_FILL_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_FILL_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_FILL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_fill_qty_mantissa,
            { DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_NAME,
              DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_FILTER,
              DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_TYPE,
              DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_MASK,
              DERIBIT_MARKETDATAAPI_FILL_QTY_MANTISSA_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_funding_8h,
            { DERIBIT_MARKETDATAAPI_FUNDING_8H_NAME,
              DERIBIT_MARKETDATAAPI_FUNDING_8H_FILTER,
              DERIBIT_MARKETDATAAPI_FUNDING_8H_TYPE,
              DERIBIT_MARKETDATAAPI_FUNDING_8H_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_FUNDING_8H_MASK,
              DERIBIT_MARKETDATAAPI_FUNDING_8H_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_implied_volatility,
            { DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_NAME,
              DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_FILTER,
              DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_TYPE,
              DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_MASK,
              DERIBIT_MARKETDATAAPI_IMPLIED_VOLATILITY_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_increment_seq_num,
            { DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_NAME,
              DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_FILTER,
              DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_TYPE,
              DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_MASK,
              DERIBIT_MARKETDATAAPI_INCREMENT_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_incremental_seq_num,
            { DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_NAME,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_FILTER,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_TYPE,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_MASK,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_incremental_timestamp,
            { DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_NAME,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_FILTER,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_TYPE,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_MASK,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_index_id,
            { DERIBIT_MARKETDATAAPI_INDEX_ID_NAME,
              DERIBIT_MARKETDATAAPI_INDEX_ID_FILTER,
              DERIBIT_MARKETDATAAPI_INDEX_ID_TYPE,
              DERIBIT_MARKETDATAAPI_INDEX_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INDEX_ID_MASK,
              DERIBIT_MARKETDATAAPI_INDEX_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_index_price,
            { DERIBIT_MARKETDATAAPI_INDEX_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_INDEX_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_INDEX_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_INDEX_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_INDEX_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_INDEX_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_instrument_id,
            { DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_NAME,
              DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_FILTER,
              DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_TYPE,
              DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_MASK,
              DERIBIT_MARKETDATAAPI_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_large_tick_size,
            { DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_NAME,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_FILTER,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_TYPE,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_MASK,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_large_tick_size_0,
            { DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_NAME,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_FILTER,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_TYPE,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_MASK,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_0_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_large_tick_size_1,
            { DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_NAME,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_FILTER,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_TYPE,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_MASK,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_SIZE_1_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_large_tick_threshold_0,
            { DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_NAME,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_FILTER,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_TYPE,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_MASK,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_0_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_large_tick_threshold_1,
            { DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_NAME,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_FILTER,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_TYPE,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_MASK,
              DERIBIT_MARKETDATAAPI_LARGE_TICK_THRESHOLD_1_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_leg_instrument_id,
            { DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_NAME,
              DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_FILTER,
              DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_TYPE,
              DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_MASK,
              DERIBIT_MARKETDATAAPI_LEG_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_maker_order_id,
            { DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_NAME,
              DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_FILTER,
              DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_TYPE,
              DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_nullable_64),
              DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_MASK,
              DERIBIT_MARKETDATAAPI_MAKER_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_mark_price,
            { DERIBIT_MARKETDATAAPI_MARK_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_MARK_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_MARK_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_MARK_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_MARK_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_MARK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_match_id,
            { DERIBIT_MARKETDATAAPI_MATCH_ID_NAME,
              DERIBIT_MARKETDATAAPI_MATCH_ID_FILTER,
              DERIBIT_MARKETDATAAPI_MATCH_ID_TYPE,
              DERIBIT_MARKETDATAAPI_MATCH_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MATCH_ID_MASK,
              DERIBIT_MARKETDATAAPI_MATCH_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_max_buy_price,
            { DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_MAX_BUY_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_message_count,
            { DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_NAME,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_FILTER,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_TYPE,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_MASK,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_message_count_short,
            { DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_NAME,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_FILTER,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_TYPE,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_MASK,
              DERIBIT_MARKETDATAAPI_MESSAGE_COUNT_SHORT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_message_length,
            { DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_NAME,
              DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_FILTER,
              DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_TYPE,
              DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_MASK,
              DERIBIT_MARKETDATAAPI_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_min_order_quantity,
            { DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_NAME,
              DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_FILTER,
              DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_TYPE,
              DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_MASK,
              DERIBIT_MARKETDATAAPI_MIN_ORDER_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_min_sell_price,
            { DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_MIN_SELL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_month,
            { DERIBIT_MARKETDATAAPI_MONTH_NAME,
              DERIBIT_MARKETDATAAPI_MONTH_FILTER,
              DERIBIT_MARKETDATAAPI_MONTH_TYPE,
              DERIBIT_MARKETDATAAPI_MONTH_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MONTH_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_name,
            { DERIBIT_MARKETDATAAPI_NAME_NAME,
              DERIBIT_MARKETDATAAPI_NAME_FILTER,
              DERIBIT_MARKETDATAAPI_NAME_TYPE,
              DERIBIT_MARKETDATAAPI_NAME_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_NAME_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_num_in_group,
            { DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_NAME,
              DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_FILTER,
              DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_TYPE,
              DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_MASK,
              DERIBIT_MARKETDATAAPI_NUM_IN_GROUP_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_number_of_legs,
            { DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_NAME,
              DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_FILTER,
              DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_TYPE,
              DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_MASK,
              DERIBIT_MARKETDATAAPI_NUMBER_OF_LEGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_order_id,
            { DERIBIT_MARKETDATAAPI_ORDER_ID_NAME,
              DERIBIT_MARKETDATAAPI_ORDER_ID_FILTER,
              DERIBIT_MARKETDATAAPI_ORDER_ID_TYPE,
              DERIBIT_MARKETDATAAPI_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_ORDER_ID_MASK,
              DERIBIT_MARKETDATAAPI_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_padding,
            { DERIBIT_MARKETDATAAPI_PADDING_NAME,
              DERIBIT_MARKETDATAAPI_PADDING_FILTER,
              DERIBIT_MARKETDATAAPI_PADDING_TYPE,
              DERIBIT_MARKETDATAAPI_PADDING_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_PADDING_MASK,
              DERIBIT_MARKETDATAAPI_PADDING_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_price,
            { DERIBIT_MARKETDATAAPI_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_PRICE_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_price_asset,
            { DERIBIT_MARKETDATAAPI_PRICE_ASSET_NAME,
              DERIBIT_MARKETDATAAPI_PRICE_ASSET_FILTER,
              DERIBIT_MARKETDATAAPI_PRICE_ASSET_TYPE,
              DERIBIT_MARKETDATAAPI_PRICE_ASSET_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_PRICE_ASSET_MASK,
              DERIBIT_MARKETDATAAPI_PRICE_ASSET_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_quantity_asset,
            { DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_NAME,
              DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_FILTER,
              DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_TYPE,
              DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_MASK,
              DERIBIT_MARKETDATAAPI_QUANTITY_ASSET_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_quantity_exponent,
            { DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_NAME,
              DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_FILTER,
              DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_TYPE,
              DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_MASK,
              DERIBIT_MARKETDATAAPI_QUANTITY_EXPONENT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_quantity_mantissa,
            { DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_NAME,
              DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_FILTER,
              DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_TYPE,
              DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_MASK,
              DERIBIT_MARKETDATAAPI_QUANTITY_MANTISSA_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_quote_currency,
            { DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_NAME,
              DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_FILTER,
              DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_TYPE,
              DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_MASK,
              DERIBIT_MARKETDATAAPI_QUOTE_CURRENCY_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_ratio,
            { DERIBIT_MARKETDATAAPI_RATIO_NAME,
              DERIBIT_MARKETDATAAPI_RATIO_FILTER,
              DERIBIT_MARKETDATAAPI_RATIO_TYPE,
              DERIBIT_MARKETDATAAPI_RATIO_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RATIO_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_reason,
            { DERIBIT_MARKETDATAAPI_REASON_NAME,
              DERIBIT_MARKETDATAAPI_REASON_FILTER,
              DERIBIT_MARKETDATAAPI_REASON_TYPE,
              DERIBIT_MARKETDATAAPI_REASON_DISPLAY,
              VALS(deribit_marketdataapi_reason_vals),
              DERIBIT_MARKETDATAAPI_REASON_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_retry_delay_nanos,
            { DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_NAME,
              DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_FILTER,
              DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_TYPE,
              DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_MASK,
              DERIBIT_MARKETDATAAPI_RETRY_DELAY_NANOS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_schema_version,
            { DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_NAME,
              DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_FILTER,
              DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_TYPE,
              DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SCHEMA_VERSION_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_sending_time,
            { DERIBIT_MARKETDATAAPI_SENDING_TIME_NAME,
              DERIBIT_MARKETDATAAPI_SENDING_TIME_FILTER,
              DERIBIT_MARKETDATAAPI_SENDING_TIME_TYPE,
              DERIBIT_MARKETDATAAPI_SENDING_TIME_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SENDING_TIME_MASK,
              DERIBIT_MARKETDATAAPI_SENDING_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_seq_num,
            { DERIBIT_MARKETDATAAPI_SEQ_NUM_NAME,
              DERIBIT_MARKETDATAAPI_SEQ_NUM_FILTER,
              DERIBIT_MARKETDATAAPI_SEQ_NUM_TYPE,
              DERIBIT_MARKETDATAAPI_SEQ_NUM_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SEQ_NUM_MASK,
              DERIBIT_MARKETDATAAPI_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_settlement_price,
            { DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_SETTLEMENT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_sort_order_id,
            { DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_NAME,
              DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_FILTER,
              DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_TYPE,
              DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_MASK,
              DERIBIT_MARKETDATAAPI_SORT_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_status,
            { DERIBIT_MARKETDATAAPI_STATUS_NAME,
              DERIBIT_MARKETDATAAPI_STATUS_FILTER,
              DERIBIT_MARKETDATAAPI_STATUS_TYPE,
              DERIBIT_MARKETDATAAPI_STATUS_DISPLAY,
              VALS(deribit_marketdataapi_status_vals),
              DERIBIT_MARKETDATAAPI_STATUS_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_strike_price,
            { DERIBIT_MARKETDATAAPI_STRIKE_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_STRIKE_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_STRIKE_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_STRIKE_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64_nullable),
              DERIBIT_MARKETDATAAPI_STRIKE_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_STRIKE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_symbol,
            { DERIBIT_MARKETDATAAPI_SYMBOL_NAME,
              DERIBIT_MARKETDATAAPI_SYMBOL_FILTER,
              DERIBIT_MARKETDATAAPI_SYMBOL_TYPE,
              DERIBIT_MARKETDATAAPI_SYMBOL_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SYMBOL_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_taker_order_id,
            { DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_NAME,
              DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_FILTER,
              DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_TYPE,
              DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_MASK,
              DERIBIT_MARKETDATAAPI_TAKER_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_template_id,
            { DERIBIT_MARKETDATAAPI_TEMPLATE_ID_NAME,
              DERIBIT_MARKETDATAAPI_TEMPLATE_ID_FILTER,
              DERIBIT_MARKETDATAAPI_TEMPLATE_ID_TYPE,
              DERIBIT_MARKETDATAAPI_TEMPLATE_ID_DISPLAY,
              VALS(deribit_marketdataapi_template_id_vals),
              DERIBIT_MARKETDATAAPI_TEMPLATE_ID_MASK,
              DERIBIT_MARKETDATAAPI_TEMPLATE_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_threshold_price,
            { DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_NAME,
              DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_FILTER,
              DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_TYPE,
              DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_MASK,
              DERIBIT_MARKETDATAAPI_THRESHOLD_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_tick_size,
            { DERIBIT_MARKETDATAAPI_TICK_SIZE_NAME,
              DERIBIT_MARKETDATAAPI_TICK_SIZE_FILTER,
              DERIBIT_MARKETDATAAPI_TICK_SIZE_TYPE,
              DERIBIT_MARKETDATAAPI_TICK_SIZE_DISPLAY,
              CF_FUNC(deribit_marketdataapi_format_decimal_9_64),
              DERIBIT_MARKETDATAAPI_TICK_SIZE_MASK,
              DERIBIT_MARKETDATAAPI_TICK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_timestamp,
            { DERIBIT_MARKETDATAAPI_TIMESTAMP_NAME,
              DERIBIT_MARKETDATAAPI_TIMESTAMP_FILTER,
              DERIBIT_MARKETDATAAPI_TIMESTAMP_TYPE,
              DERIBIT_MARKETDATAAPI_TIMESTAMP_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TIMESTAMP_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_total_filled_mantissa,
            { DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_NAME,
              DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_FILTER,
              DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_TYPE,
              DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_MASK,
              DERIBIT_MARKETDATAAPI_TOTAL_FILLED_MANTISSA_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_trade_count,
            { DERIBIT_MARKETDATAAPI_TRADE_COUNT_NAME,
              DERIBIT_MARKETDATAAPI_TRADE_COUNT_FILTER,
              DERIBIT_MARKETDATAAPI_TRADE_COUNT_TYPE,
              DERIBIT_MARKETDATAAPI_TRADE_COUNT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TRADE_COUNT_MASK,
              DERIBIT_MARKETDATAAPI_TRADE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_trading_status,
            { DERIBIT_MARKETDATAAPI_TRADING_STATUS_NAME,
              DERIBIT_MARKETDATAAPI_TRADING_STATUS_FILTER,
              DERIBIT_MARKETDATAAPI_TRADING_STATUS_TYPE,
              DERIBIT_MARKETDATAAPI_TRADING_STATUS_DISPLAY,
              VALS(deribit_marketdataapi_trading_status_vals),
              DERIBIT_MARKETDATAAPI_TRADING_STATUS_MASK,
              DERIBIT_MARKETDATAAPI_TRADING_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_transact_time,
            { DERIBIT_MARKETDATAAPI_TRANSACT_TIME_NAME,
              DERIBIT_MARKETDATAAPI_TRANSACT_TIME_FILTER,
              DERIBIT_MARKETDATAAPI_TRANSACT_TIME_TYPE,
              DERIBIT_MARKETDATAAPI_TRANSACT_TIME_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TRANSACT_TIME_MASK,
              DERIBIT_MARKETDATAAPI_TRANSACT_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_type,
            { DERIBIT_MARKETDATAAPI_TYPE_NAME,
              DERIBIT_MARKETDATAAPI_TYPE_FILTER,
              DERIBIT_MARKETDATAAPI_TYPE_TYPE,
              DERIBIT_MARKETDATAAPI_TYPE_DISPLAY,
              VALS(deribit_marketdataapi_type_vals),
              DERIBIT_MARKETDATAAPI_TYPE_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_underlying,
            { DERIBIT_MARKETDATAAPI_UNDERLYING_NAME,
              DERIBIT_MARKETDATAAPI_UNDERLYING_FILTER,
              DERIBIT_MARKETDATAAPI_UNDERLYING_TYPE,
              DERIBIT_MARKETDATAAPI_UNDERLYING_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_UNDERLYING_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_marketdataapi_week_of_month,
            { DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_NAME,
              DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_FILTER,
              DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_TYPE,
              DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_MASK,
              DERIBIT_MARKETDATAAPI_WEEK_OF_MONTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_year,
            { DERIBIT_MARKETDATAAPI_YEAR_NAME,
              DERIBIT_MARKETDATAAPI_YEAR_FILTER,
              DERIBIT_MARKETDATAAPI_YEAR_TYPE,
              DERIBIT_MARKETDATAAPI_YEAR_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_YEAR_MASK,
              NULL,
              HFILL } },

        /* Bit Fields */
        { &hf_deribit_marketdataapi_end_of_transaction,
            { DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_NAME,
              DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_FILTER,
              DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_TYPE,
              DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_MASK,
              DERIBIT_MARKETDATAAPI_END_OF_TRANSACTION_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_incremental_update,
            { DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_NAME,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_FILTER,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_TYPE,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_MASK,
              DERIBIT_MARKETDATAAPI_INCREMENTAL_UPDATE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_is_liquidation,
            { DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_NAME,
              DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_FILTER,
              DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_TYPE,
              DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_MASK,
              DERIBIT_MARKETDATAAPI_IS_LIQUIDATION_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_is_perpetual,
            { DERIBIT_MARKETDATAAPI_IS_PERPETUAL_NAME,
              DERIBIT_MARKETDATAAPI_IS_PERPETUAL_FILTER,
              DERIBIT_MARKETDATAAPI_IS_PERPETUAL_TYPE,
              DERIBIT_MARKETDATAAPI_IS_PERPETUAL_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_IS_PERPETUAL_MASK,
              DERIBIT_MARKETDATAAPI_IS_PERPETUAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_is_put_option,
            { DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_NAME,
              DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_FILTER,
              DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_TYPE,
              DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_MASK,
              DERIBIT_MARKETDATAAPI_IS_PUT_OPTION_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_is_reversed,
            { DERIBIT_MARKETDATAAPI_IS_REVERSED_NAME,
              DERIBIT_MARKETDATAAPI_IS_REVERSED_FILTER,
              DERIBIT_MARKETDATAAPI_IS_REVERSED_TYPE,
              DERIBIT_MARKETDATAAPI_IS_REVERSED_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_IS_REVERSED_MASK,
              DERIBIT_MARKETDATAAPI_IS_REVERSED_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_is_sell,
            { DERIBIT_MARKETDATAAPI_IS_SELL_NAME,
              DERIBIT_MARKETDATAAPI_IS_SELL_FILTER,
              DERIBIT_MARKETDATAAPI_IS_SELL_TYPE,
              DERIBIT_MARKETDATAAPI_IS_SELL_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_IS_SELL_MASK,
              DERIBIT_MARKETDATAAPI_IS_SELL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_reserved_29,
            { DERIBIT_MARKETDATAAPI_RESERVED_29_NAME,
              DERIBIT_MARKETDATAAPI_RESERVED_29_FILTER,
              DERIBIT_MARKETDATAAPI_RESERVED_29_TYPE,
              DERIBIT_MARKETDATAAPI_RESERVED_29_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RESERVED_29_MASK,
              DERIBIT_MARKETDATAAPI_RESERVED_29_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_reserved_30,
            { DERIBIT_MARKETDATAAPI_RESERVED_30_NAME,
              DERIBIT_MARKETDATAAPI_RESERVED_30_FILTER,
              DERIBIT_MARKETDATAAPI_RESERVED_30_TYPE,
              DERIBIT_MARKETDATAAPI_RESERVED_30_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RESERVED_30_MASK,
              DERIBIT_MARKETDATAAPI_RESERVED_30_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_reserved_5,
            { DERIBIT_MARKETDATAAPI_RESERVED_5_NAME,
              DERIBIT_MARKETDATAAPI_RESERVED_5_FILTER,
              DERIBIT_MARKETDATAAPI_RESERVED_5_TYPE,
              DERIBIT_MARKETDATAAPI_RESERVED_5_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RESERVED_5_MASK,
              DERIBIT_MARKETDATAAPI_RESERVED_5_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_retransmit,
            { DERIBIT_MARKETDATAAPI_RETRANSMIT_NAME,
              DERIBIT_MARKETDATAAPI_RETRANSMIT_FILTER,
              DERIBIT_MARKETDATAAPI_RETRANSMIT_TYPE,
              DERIBIT_MARKETDATAAPI_RETRANSMIT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_RETRANSMIT_MASK,
              DERIBIT_MARKETDATAAPI_RETRANSMIT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_snapshot,
            { DERIBIT_MARKETDATAAPI_SNAPSHOT_NAME,
              DERIBIT_MARKETDATAAPI_SNAPSHOT_FILTER,
              DERIBIT_MARKETDATAAPI_SNAPSHOT_TYPE,
              DERIBIT_MARKETDATAAPI_SNAPSHOT_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_SNAPSHOT_MASK,
              DERIBIT_MARKETDATAAPI_SNAPSHOT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_start_of_transaction,
            { DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_NAME,
              DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_FILTER,
              DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_TYPE,
              DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_MASK,
              DERIBIT_MARKETDATAAPI_START_OF_TRANSACTION_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_deribit_marketdataapi_packet_type,
            { DERIBIT_MARKETDATAAPI_PACKET_TYPE_NAME,
              DERIBIT_MARKETDATAAPI_PACKET_TYPE_FILTER,
              DERIBIT_MARKETDATAAPI_PACKET_TYPE_TYPE,
              DERIBIT_MARKETDATAAPI_PACKET_TYPE_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_PACKET_TYPE_MASK,
              DERIBIT_MARKETDATAAPI_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_message_flags,
            { DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_NAME,
              DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_FILTER,
              DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_TYPE,
              DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_MASK,
              DERIBIT_MARKETDATAAPI_MESSAGE_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_flags,
            { DERIBIT_MARKETDATAAPI_FLAGS_NAME,
              DERIBIT_MARKETDATAAPI_FLAGS_FILTER,
              DERIBIT_MARKETDATAAPI_FLAGS_TYPE,
              DERIBIT_MARKETDATAAPI_FLAGS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_FLAGS_MASK,
              DERIBIT_MARKETDATAAPI_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_taker_flags,
            { DERIBIT_MARKETDATAAPI_TAKER_FLAGS_NAME,
              DERIBIT_MARKETDATAAPI_TAKER_FLAGS_FILTER,
              DERIBIT_MARKETDATAAPI_TAKER_FLAGS_TYPE,
              DERIBIT_MARKETDATAAPI_TAKER_FLAGS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_TAKER_FLAGS_MASK,
              DERIBIT_MARKETDATAAPI_TAKER_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_maker_flags,
            { DERIBIT_MARKETDATAAPI_MAKER_FLAGS_NAME,
              DERIBIT_MARKETDATAAPI_MAKER_FLAGS_FILTER,
              DERIBIT_MARKETDATAAPI_MAKER_FLAGS_TYPE,
              DERIBIT_MARKETDATAAPI_MAKER_FLAGS_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_MAKER_FLAGS_MASK,
              DERIBIT_MARKETDATAAPI_MAKER_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_marketdataapi_flags_v01,
            { DERIBIT_MARKETDATAAPI_FLAGS_V01_NAME,
              DERIBIT_MARKETDATAAPI_FLAGS_V01_FILTER,
              DERIBIT_MARKETDATAAPI_FLAGS_V01_TYPE,
              DERIBIT_MARKETDATAAPI_FLAGS_V01_DISPLAY,
              NULL,
              DERIBIT_MARKETDATAAPI_FLAGS_V01_MASK,
              DERIBIT_MARKETDATAAPI_FLAGS_V01_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_deribit_marketdataapi,
        &ett_deribit_marketdataapi_header,
        &ett_deribit_marketdataapi_message,
        &ett_deribit_marketdataapi_packet_type,
        &ett_deribit_marketdataapi_message_flags,
        &ett_deribit_marketdataapi_flags,
        &ett_deribit_marketdataapi_taker_flags,
        &ett_deribit_marketdataapi_maker_flags,
        &ett_deribit_marketdataapi_flags_v01,
        &ett_deribit_marketdataapi_md_message_header,
        &ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_groups,
        &ett_deribit_marketdataapi_group_size_encoding,
        &ett_deribit_marketdataapi_instrument_definition_message_large_tick_sizes_group,
        &ett_deribit_marketdataapi_instrument_definition_message_legs_groups,
        &ett_deribit_marketdataapi_instrument_definition_message_legs_group,
        &ett_deribit_marketdataapi_logical_expiry,
    };

    static ei_register_info ei[] = {
        { &ei_deribit_marketdataapi_length,
            { DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_FILTER,
              DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_GROUP,
              DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_SEVERITY,
              DERIBIT_MARKETDATAAPI_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_deribit_marketdataapi = proto_register_protocol(DERIBIT_MARKETDATAAPI_PROTOCOL_NAME, DERIBIT_MARKETDATAAPI_PROTOCOL_SHORT, DERIBIT_MARKETDATAAPI_PROTOCOL_FILTER);

    proto_register_field_array(proto_deribit_marketdataapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_deribit_marketdataapi = expert_register_protocol(proto_deribit_marketdataapi);
    expert_register_field_array(expert_deribit_marketdataapi, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_deribit_marketdataapi, NULL);

    prefs_register_enum_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_VERSION_PREFERENCE_DESCRIPTION,
        &deribit_marketdataapi_pref_version,
        deribit_marketdataapi_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &deribit_marketdataapi_show_headers);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &deribit_marketdataapi_show_application_messages);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION,
        &deribit_marketdataapi_show_structs);

    prefs_register_uint_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &deribit_marketdataapi_pref_decimal_places);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_NAME,
        DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_TITLE,
        DERIBIT_MARKETDATAAPI_INDEXES_PREFERENCE_DESCRIPTION,
        &deribit_marketdataapi_pref_show_indexes);

    deribit_marketdataapi_handle = register_dissector(DERIBIT_MARKETDATAAPI_PROTOCOL_FILTER, dissect_deribit_marketdataapi, proto_deribit_marketdataapi);
}

void
proto_reg_handoff_deribit_marketdataapi(void)
{
    heur_dissector_add("udp", dissect_deribit_marketdataapi_heur, "Deribit MarketDataApi over UDP",
        "deribit_marketdataapi_udp", proto_deribit_marketdataapi, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("udp.port", deribit_marketdataapi_handle);
}
