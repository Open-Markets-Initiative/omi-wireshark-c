/* packet-coinbasederivatives-marketdataapi.c
 * Routines for CoinbaseDerivatives MarketDataApi dissection
 *
 * Aggregated protocol versions: 1.9, 1.7, 1.3, 1.2
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Coinbase.CoinbaseDerivatives.MarketDataApi.Sbe.v1.9
 *   Coinbase.CoinbaseDerivatives.MarketDataApi.Sbe.v1.7
 *   Coinbase.CoinbaseDerivatives.MarketDataApi.Sbe.v1.3
 *   Coinbase.CoinbaseDerivatives.MarketDataApi.Sbe.v1.2
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

void proto_register_coinbasederivatives_marketdataapi(void);
void proto_reg_handoff_coinbasederivatives_marketdataapi(void);

static dissector_handle_t coinbasederivatives_marketdataapi_handle;

static int proto_coinbasederivatives_marketdataapi;

/*
 * CoinbaseDerivatives MarketDataApi Protocol
 */

#define COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_NAME "CoinbaseDerivatives MarketDataApi"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_SHORT "COINBASEDERIVATIVES.MARKETDATAAPI"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_FILTER "coinbasederivatives.marketdataapi"

/*
 * CoinbaseDerivatives MarketDataApi Header
 */

#define COINBASEDERIVATIVES_MARKETDATAAPI_HEADER_SIZE 24 /* Packet Header */

/*
 * CoinbaseDerivatives MarketDataApi Field Handles
 */

static int hf_coinbasederivatives_marketdataapi_active_instrument_count;
static int hf_coinbasederivatives_marketdataapi_aggressor_order_id;
static int hf_coinbasederivatives_marketdataapi_aggressor_receive_time;
static int hf_coinbasederivatives_marketdataapi_begin_seq_num;
static int hf_coinbasederivatives_marketdataapi_best_ask_implied_price;
static int hf_coinbasederivatives_marketdataapi_best_ask_implied_qty;
static int hf_coinbasederivatives_marketdataapi_best_bid_implied_price;
static int hf_coinbasederivatives_marketdataapi_best_bid_implied_qty;
static int hf_coinbasederivatives_marketdataapi_best_price;
static int hf_coinbasederivatives_marketdataapi_best_price_v12;
static int hf_coinbasederivatives_marketdataapi_best_qty;
static int hf_coinbasederivatives_marketdataapi_block_length;
static int hf_coinbasederivatives_marketdataapi_buy_order_id;
static int hf_coinbasederivatives_marketdataapi_cfi_code;
static int hf_coinbasederivatives_marketdataapi_channel_id;
static int hf_coinbasederivatives_marketdataapi_close_price;
static int hf_coinbasederivatives_marketdataapi_contract_size;
static int hf_coinbasederivatives_marketdataapi_contract_size_v13;
static int hf_coinbasederivatives_marketdataapi_correlation_id;
static int hf_coinbasederivatives_marketdataapi_currency;
static int hf_coinbasederivatives_marketdataapi_day_of_month;
static int hf_coinbasederivatives_marketdataapi_day_open_price;
static int hf_coinbasederivatives_marketdataapi_deepest_price;
static int hf_coinbasederivatives_marketdataapi_deepest_price_v12;
static int hf_coinbasederivatives_marketdataapi_definition_flags;
static int hf_coinbasederivatives_marketdataapi_definition_flags_v17;
static int hf_coinbasederivatives_marketdataapi_definition_flags_v13;
static int hf_coinbasederivatives_marketdataapi_definition_flags_v12;
static int hf_coinbasederivatives_marketdataapi_description;
static int hf_coinbasederivatives_marketdataapi_details;
static int hf_coinbasederivatives_marketdataapi_fair_value;
static int hf_coinbasederivatives_marketdataapi_fair_value_limit;
static int hf_coinbasederivatives_marketdataapi_fair_value_optional;
static int hf_coinbasederivatives_marketdataapi_final_funding_rate;
static int hf_coinbasederivatives_marketdataapi_final_funding_rate_timestamp;
static int hf_coinbasederivatives_marketdataapi_final_futures_mark_price;
static int hf_coinbasederivatives_marketdataapi_first_trading_session_date;
static int hf_coinbasederivatives_marketdataapi_flags;
static int hf_coinbasederivatives_marketdataapi_frame_length;
static int hf_coinbasederivatives_marketdataapi_funding_interval_minutes;
static int hf_coinbasederivatives_marketdataapi_funding_rate;
static int hf_coinbasederivatives_marketdataapi_funding_rate_applicable;
static int hf_coinbasederivatives_marketdataapi_futures_mark_price;
static int hf_coinbasederivatives_marketdataapi_futures_mark_price_optional;
static int hf_coinbasederivatives_marketdataapi_high_price;
static int hf_coinbasederivatives_marketdataapi_incremental_update;
static int hf_coinbasederivatives_marketdataapi_indicative_open_price;
static int hf_coinbasederivatives_marketdataapi_instr_seq_num;
static int hf_coinbasederivatives_marketdataapi_instrument_flags;
static int hf_coinbasederivatives_marketdataapi_instrument_id;
static int hf_coinbasederivatives_marketdataapi_instrument_side;
static int hf_coinbasederivatives_marketdataapi_is_announced;
static int hf_coinbasederivatives_marketdataapi_is_call;
static int hf_coinbasederivatives_marketdataapi_is_final;
static int hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical;
static int hf_coinbasederivatives_marketdataapi_is_strike_delisted;
static int hf_coinbasederivatives_marketdataapi_large_tick;
static int hf_coinbasederivatives_marketdataapi_large_tick_threshold;
static int hf_coinbasederivatives_marketdataapi_last_instr_seq_num;
static int hf_coinbasederivatives_marketdataapi_last_trade_price;
static int hf_coinbasederivatives_marketdataapi_last_trade_qty;
static int hf_coinbasederivatives_marketdataapi_last_trade_time;
static int hf_coinbasederivatives_marketdataapi_last_trading_session_date;
static int hf_coinbasederivatives_marketdataapi_leg_1_instrument_id;
static int hf_coinbasederivatives_marketdataapi_leg_2_instrument_id;
static int hf_coinbasederivatives_marketdataapi_limit_down_price;
static int hf_coinbasederivatives_marketdataapi_limit_up_price;
static int hf_coinbasederivatives_marketdataapi_low_price;
static int hf_coinbasederivatives_marketdataapi_match_id;
static int hf_coinbasederivatives_marketdataapi_message_count;
static int hf_coinbasederivatives_marketdataapi_month;
static int hf_coinbasederivatives_marketdataapi_new_leg_1_price;
static int hf_coinbasederivatives_marketdataapi_new_leg_1_price_v12;
static int hf_coinbasederivatives_marketdataapi_new_leg_2_price;
static int hf_coinbasederivatives_marketdataapi_new_leg_2_price_v12;
static int hf_coinbasederivatives_marketdataapi_new_price;
static int hf_coinbasederivatives_marketdataapi_new_price_v12;
static int hf_coinbasederivatives_marketdataapi_next_ask_implied_price;
static int hf_coinbasederivatives_marketdataapi_next_ask_implied_qty;
static int hf_coinbasederivatives_marketdataapi_next_bid_implied_price;
static int hf_coinbasederivatives_marketdataapi_next_bid_implied_qty;
static int hf_coinbasederivatives_marketdataapi_next_price;
static int hf_coinbasederivatives_marketdataapi_next_price_v12;
static int hf_coinbasederivatives_marketdataapi_next_qty;
static int hf_coinbasederivatives_marketdataapi_old_contract_size;
static int hf_coinbasederivatives_marketdataapi_old_leg_1_price;
static int hf_coinbasederivatives_marketdataapi_old_leg_1_price_v12;
static int hf_coinbasederivatives_marketdataapi_old_leg_2_price;
static int hf_coinbasederivatives_marketdataapi_old_leg_2_price_v12;
static int hf_coinbasederivatives_marketdataapi_old_price;
static int hf_coinbasederivatives_marketdataapi_old_price_v12;
static int hf_coinbasederivatives_marketdataapi_open_interest;
static int hf_coinbasederivatives_marketdataapi_option_expiry_type;
static int hf_coinbasederivatives_marketdataapi_order_count;
static int hf_coinbasederivatives_marketdataapi_order_id;
static int hf_coinbasederivatives_marketdataapi_packet_flags;
static int hf_coinbasederivatives_marketdataapi_padding;
static int hf_coinbasederivatives_marketdataapi_predicted_funding_rate;
static int hf_coinbasederivatives_marketdataapi_price;
static int hf_coinbasederivatives_marketdataapi_price_increment;
static int hf_coinbasederivatives_marketdataapi_prior_settlement_price;
static int hf_coinbasederivatives_marketdataapi_prior_settlement_price_v12;
static int hf_coinbasederivatives_marketdataapi_prior_settlement_price_optional;
static int hf_coinbasederivatives_marketdataapi_product_code;
static int hf_coinbasederivatives_marketdataapi_product_group;
static int hf_coinbasederivatives_marketdataapi_product_id;
static int hf_coinbasederivatives_marketdataapi_quantity;
static int hf_coinbasederivatives_marketdataapi_reason;
static int hf_coinbasederivatives_marketdataapi_reserved;
static int hf_coinbasederivatives_marketdataapi_reserved_11;
static int hf_coinbasederivatives_marketdataapi_reserved_12;
static int hf_coinbasederivatives_marketdataapi_reserved_13;
static int hf_coinbasederivatives_marketdataapi_reserved_15;
static int hf_coinbasederivatives_marketdataapi_reserved_7;
static int hf_coinbasederivatives_marketdataapi_retransmit;
static int hf_coinbasederivatives_marketdataapi_retry_delay_nanos;
static int hf_coinbasederivatives_marketdataapi_schema_id;
static int hf_coinbasederivatives_marketdataapi_sell_order_id;
static int hf_coinbasederivatives_marketdataapi_sending_time;
static int hf_coinbasederivatives_marketdataapi_seq_num;
static int hf_coinbasederivatives_marketdataapi_settlement_price;
static int hf_coinbasederivatives_marketdataapi_small_tick;
static int hf_coinbasederivatives_marketdataapi_snapshot;
static int hf_coinbasederivatives_marketdataapi_snapshot_instrument_id;
static int hf_coinbasederivatives_marketdataapi_snapshot_seq_num;
static int hf_coinbasederivatives_marketdataapi_spot_mark_price;
static int hf_coinbasederivatives_marketdataapi_spot_mark_price_optional;
static int hf_coinbasederivatives_marketdataapi_spread_buy_convention;
static int hf_coinbasederivatives_marketdataapi_stat_type;
static int hf_coinbasederivatives_marketdataapi_strike_price;
static int hf_coinbasederivatives_marketdataapi_symbol;
static int hf_coinbasederivatives_marketdataapi_template_id;
static int hf_coinbasederivatives_marketdataapi_tick_size;
static int hf_coinbasederivatives_marketdataapi_trade_volume;
static int hf_coinbasederivatives_marketdataapi_trading_session_date;
static int hf_coinbasederivatives_marketdataapi_trading_status;
static int hf_coinbasederivatives_marketdataapi_transact_time;
static int hf_coinbasederivatives_marketdataapi_underlying_instrument_id;
static int hf_coinbasederivatives_marketdataapi_version;
static int hf_coinbasederivatives_marketdataapi_vwap_price;
static int hf_coinbasederivatives_marketdataapi_vwap_price_optional;
static int hf_coinbasederivatives_marketdataapi_week_of_month;
static int hf_coinbasederivatives_marketdataapi_year;

/*
 * CoinbaseDerivatives MarketDataApi Subtrees
 */

static int ett_coinbasederivatives_marketdataapi;
static int ett_coinbasederivatives_marketdataapi_header;
static int ett_coinbasederivatives_marketdataapi_message;
static int ett_coinbasederivatives_marketdataapi_packet_flags;
static int ett_coinbasederivatives_marketdataapi_definition_flags;
static int ett_coinbasederivatives_marketdataapi_flags;
static int ett_coinbasederivatives_marketdataapi_definition_flags_v17;
static int ett_coinbasederivatives_marketdataapi_definition_flags_v13;
static int ett_coinbasederivatives_marketdataapi_definition_flags_v12;
static int ett_coinbasederivatives_marketdataapi_message_header;
static int ett_coinbasederivatives_marketdataapi_instr_header;
static int ett_coinbasederivatives_marketdataapi_logical_expiry;

/*
 * CoinbaseDerivatives MarketDataApi Expert Information
 */

/* Message length does not account for the parsed fields */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_FILTER "coinbasederivatives.marketdataapi.length.invalid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_GROUP PI_MALFORMED
#define COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_SEVERITY PI_ERROR
#define COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_coinbasederivatives_marketdataapi_length;

/*
 * CoinbaseDerivatives MarketDataApi Preferences
 */

#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_NAME "version"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_TITLE "Protocol version"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_AUTOMATIC 0
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_9     1
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7     2
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3     3
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2     4

static const enum_val_t coinbasederivatives_marketdataapi_version_vals[] = {
    { "automatic", "Automatic (by send time)", COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_AUTOMATIC },
    { "v1.9", "1.9", COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_9 },
    { "v1.7", "1.7", COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7 },
    { "v1.3", "1.3", COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3 },
    { "v1.2", "1.2", COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
coinbasederivatives_marketdataapi_version_name(int version)
{
    switch (version) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_9:
        return "1.9";
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7:
        return "1.7";
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3:
        return "1.3";
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2:
        return "1.2";
    }

    return "";
}

static int coinbasederivatives_marketdataapi_pref_version = COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_9 UINT64_C(1757030400) /* 2025-09-05 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_7 UINT64_C(1649894400) /* 2022-04-14 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_3 UINT64_C(1624838400) /* 2021-06-28 */

/* Show preferences, one per message and struct */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_NAME "show.structs"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_TITLE "Show Structs"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION "Show Structs in the protocol tree"

static bool coinbasederivatives_marketdataapi_show_headers = true;
static bool coinbasederivatives_marketdataapi_show_application_messages = true;
static bool coinbasederivatives_marketdataapi_show_structs = true;

/* Decimal places shown, the wire precision by default */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_NAME "decimal.places"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned coinbasederivatives_marketdataapi_pref_decimal_places = 9;

/* Ports the feed arrives on, assigned per deployment */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_NAME "ports"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_TITLE "Ports"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_DEFAULT "5222,5223,5224,5225"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *coinbasederivatives_marketdataapi_pref_ports;

/*
 * CoinbaseDerivatives MarketDataApi Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
coinbasederivatives_marketdataapi_version(uint64_t seconds, int declared)
{
    if (coinbasederivatives_marketdataapi_pref_version != COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_AUTOMATIC) {
        return coinbasederivatives_marketdataapi_pref_version;
    }

    switch (declared) {
    case 9: return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_9;
    case 7: return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7;
    case 3: return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3;
    case 2: return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2;
    }

    if (seconds >= COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_9) {
        return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_9;
    }

    if (seconds >= COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_7) {
        return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7;
    }

    if (seconds >= COINBASEDERIVATIVES_MARKETDATAAPI_EFFECTIVE_1_3) {
        return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3;
    }

    return COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2;
}

/* Cap the fraction at the preferred decimal places */
static void
coinbasederivatives_marketdataapi_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = coinbasederivatives_marketdataapi_pref_decimal_places;

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
coinbasederivatives_marketdataapi_format_decimal_9_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t whole = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && whole == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, whole, fraction);
    }

    coinbasederivatives_marketdataapi_decimal_places(buf);
}

/* Format an implied 9 decimal place value */
static void
coinbasederivatives_marketdataapi_format_decimal_9_64_nullable(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }
    int64_t whole = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && whole == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, whole, fraction);
    }

    coinbasederivatives_marketdataapi_decimal_places(buf);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
coinbasederivatives_marketdataapi_format_nullable_32(char *buf, uint32_t raw)
{
    int64_t value = (int32_t)raw;

    if (value == INT32_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
coinbasederivatives_marketdataapi_format_nullable_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/*
 * CoinbaseDerivatives MarketDataApi Fields
 */

/* Active Instrument Count */
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_NAME        "Active Instrument Count"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DESCRIPTION "activeInstrumentCount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_FILTER      "coinbasederivatives.marketdataapi.activeinstrumentcount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_active_instrument_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_active_instrument_count, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_SIZE;
}

/* Aggressor Order Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_NAME        "Aggressor Order Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_DESCRIPTION "aggressorOrderId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_FILTER      "coinbasederivatives.marketdataapi.aggressororderid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_aggressor_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_aggressor_order_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_SIZE;
}

/* Aggressor Receive Time */
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_NAME        "Aggressor Receive Time"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_DESCRIPTION "aggressorReceiveTime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_FILTER      "coinbasederivatives.marketdataapi.aggressorreceivetime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_aggressor_receive_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_aggressor_receive_time, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_SIZE;
}

/* Begin Seq Num */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_NAME        "Begin Seq Num"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_DESCRIPTION "beginSeqNum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_FILTER      "coinbasederivatives.marketdataapi.beginseqnum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_begin_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_begin_seq_num, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_SIZE;
}

/* Best Ask Implied Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_NAME        "Best Ask Implied Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_DESCRIPTION "bestAskImpliedPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_FILTER      "coinbasederivatives.marketdataapi.bestaskimpliedprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_best_ask_implied_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_ask_implied_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_SIZE;
}

/* Best Ask Implied Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_NAME        "Best Ask Implied Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_DESCRIPTION "bestAskImpliedQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_FILTER      "coinbasederivatives.marketdataapi.bestaskimpliedqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_best_ask_implied_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_ask_implied_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_SIZE;
}

/* Best Bid Implied Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_NAME        "Best Bid Implied Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_DESCRIPTION "bestBidImpliedPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_FILTER      "coinbasederivatives.marketdataapi.bestbidimpliedprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_best_bid_implied_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_bid_implied_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_SIZE;
}

/* Best Bid Implied Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_NAME        "Best Bid Implied Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_DESCRIPTION "bestBidImpliedQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_FILTER      "coinbasederivatives.marketdataapi.bestbidimpliedqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_best_bid_implied_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_bid_implied_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_SIZE;
}

/* Best Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_NAME        "Best Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_DESCRIPTION "bestPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_FILTER      "coinbasederivatives.marketdataapi.bestprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_best_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_SIZE;
}

/* Best Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_NAME        "Best Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_DESCRIPTION "bestPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.bestprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_best_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_SIZE;
}

/* Best Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_NAME        "Best Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_DESCRIPTION "bestQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_FILTER      "coinbasederivatives.marketdataapi.bestqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_best_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_best_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_SIZE;
}

/* Block Length */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_NAME        "Block Length"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_DESCRIPTION "Length of message body excluding this header and any repeating groups or variable-length fields"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_FILTER      "coinbasederivatives.marketdataapi.blocklength"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_block_length, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_SIZE;
}

/* Buy Order Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_NAME        "Buy Order Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_DESCRIPTION "buyOrderId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_FILTER      "coinbasederivatives.marketdataapi.buyorderid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_buy_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_buy_order_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_SIZE;
}

/* Cfi Code */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_NAME        "Cfi Code"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_DESCRIPTION "cfiCode"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_FILTER      "coinbasederivatives.marketdataapi.cficode"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_cfi_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_cfi_code, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_SIZE;
}

/* Channel Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_NAME        "Channel Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_DESCRIPTION "Channel identifier for product/instrument set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_FILTER      "coinbasederivatives.marketdataapi.channelid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_channel_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_channel_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_SIZE;
}

/* Close Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_NAME        "Close Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_DESCRIPTION "closePrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_FILTER      "coinbasederivatives.marketdataapi.closeprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_close_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_close_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_SIZE;
}

/* Contract Size */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_NAME        "Contract Size"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_DESCRIPTION "contractSize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_FILTER      "coinbasederivatives.marketdataapi.contractsize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_contract_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_contract_size, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_SIZE;
}

/* Contract Size V13 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_NAME        "Contract Size"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_DESCRIPTION "contractSize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_FILTER      "coinbasederivatives.marketdataapi.contractsize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_contract_size_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_contract_size_v13, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_SIZE;
}

/* Correlation Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_NAME        "Correlation Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_DESCRIPTION "correlationId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_FILTER      "coinbasederivatives.marketdataapi.correlationid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_correlation_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_correlation_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_SIZE;
}

/* Currency */
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_NAME        "Currency"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_DESCRIPTION "currency"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_FILTER      "coinbasederivatives.marketdataapi.currency"
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_currency(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_currency, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_SIZE;
}

/* Day Of Month */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_NAME        "Day Of Month"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_DESCRIPTION "dayOfMonth"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_FILTER      "coinbasederivatives.marketdataapi.dayofmonth"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_TYPE        FT_INT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_day_of_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_day_of_month, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_SIZE;
}

/* Day Open Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_NAME        "Day Open Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_DESCRIPTION "dayOpenPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_FILTER      "coinbasederivatives.marketdataapi.dayopenprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_day_open_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_day_open_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_SIZE;
}

/* Deepest Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_NAME        "Deepest Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_DESCRIPTION "deepestPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_FILTER      "coinbasederivatives.marketdataapi.deepestprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_deepest_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_deepest_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_SIZE;
}

/* Deepest Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_NAME        "Deepest Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_DESCRIPTION "deepestPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.deepestprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_deepest_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_deepest_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_SIZE;
}

/* Description */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_NAME        "Description"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_DESCRIPTION "description"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_FILTER      "coinbasederivatives.marketdataapi.description"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_SIZE        32

static unsigned
parse_coinbasederivatives_marketdataapi_description(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_description, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_SIZE;
}

/* Details */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_NAME        "Details"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_DESCRIPTION "details"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_FILTER      "coinbasederivatives.marketdataapi.details"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_SIZE        40

static unsigned
parse_coinbasederivatives_marketdataapi_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_details, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_SIZE;
}

/* Fair Value */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_NAME        "Fair Value"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_DESCRIPTION "fairValue"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_FILTER      "coinbasederivatives.marketdataapi.fairvalue"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_fair_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_fair_value, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_SIZE;
}

/* Fair Value Limit */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_NAME        "Fair Value Limit"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_DESCRIPTION "fairValueLimit"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_FILTER      "coinbasederivatives.marketdataapi.fairvaluelimit"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_fair_value_limit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_fair_value_limit, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_SIZE;
}

/* Fair Value Optional */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_NAME        "Fair Value Optional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_DESCRIPTION "fairValue"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_FILTER      "coinbasederivatives.marketdataapi.fairvalueoptional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_fair_value_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_fair_value_optional, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_SIZE;
}

/* Final Funding Rate */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_NAME        "Final Funding Rate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_DESCRIPTION "finalFundingRate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_FILTER      "coinbasederivatives.marketdataapi.finalfundingrate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_final_funding_rate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_final_funding_rate, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_SIZE;
}

/* Final Funding Rate Timestamp */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_NAME        "Final Funding Rate Timestamp"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_DESCRIPTION "finalFundingRateTimestamp"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_FILTER      "coinbasederivatives.marketdataapi.finalfundingratetimestamp"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_final_funding_rate_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_final_funding_rate_timestamp, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_SIZE;
}

/* Final Futures Mark Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_NAME        "Final Futures Mark Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_DESCRIPTION "finalFuturesMarkPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_FILTER      "coinbasederivatives.marketdataapi.finalfuturesmarkprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_final_futures_mark_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_final_futures_mark_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_SIZE;
}

/* First Trading Session Date */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_NAME        "First Trading Session Date"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_DESCRIPTION "firstTradingSessionDate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_FILTER      "coinbasederivatives.marketdataapi.firsttradingsessiondate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    nstime_t date = { .secs = (time_t)tvb_get_letohs(tvb, offset) * 86400, .nsecs = 0 };

    proto_tree_add_time(tree, hf_coinbasederivatives_marketdataapi_first_trading_session_date, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_SIZE, &date);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_SIZE;
}

/* Frame Length */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_NAME        "Frame Length"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_DESCRIPTION "Total message size in bytes including this header"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_FILTER      "coinbasederivatives.marketdataapi.framelength"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_frame_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_frame_length, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_SIZE;
}

/* Funding Interval Minutes */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_NAME        "Funding Interval Minutes"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_DESCRIPTION "fundingIntervalMinutes"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_FILTER      "coinbasederivatives.marketdataapi.fundingintervalminutes"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_funding_interval_minutes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_funding_interval_minutes, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_SIZE;
}

/* Funding Rate */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_NAME        "Funding Rate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_DESCRIPTION "fundingRate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_FILTER      "coinbasederivatives.marketdataapi.fundingrate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_funding_rate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_funding_rate, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_SIZE;
}

/* Funding Rate Applicable */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_NAME        "Funding Rate Applicable"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_DESCRIPTION "fundingRateApplicable"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_FILTER      "coinbasederivatives.marketdataapi.fundingrateapplicable"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_MASK        0x10

/* Futures Mark Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_NAME        "Futures Mark Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_DESCRIPTION "futuresMarkPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_FILTER      "coinbasederivatives.marketdataapi.futuresmarkprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_futures_mark_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_futures_mark_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_SIZE;
}

/* Futures Mark Price Optional */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_NAME        "Futures Mark Price Optional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_DESCRIPTION "futuresMarkPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_FILTER      "coinbasederivatives.marketdataapi.futuresmarkpriceoptional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_futures_mark_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_futures_mark_price_optional, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_SIZE;
}

/* High Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_NAME        "High Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_DESCRIPTION "highPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_FILTER      "coinbasederivatives.marketdataapi.highprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_high_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_high_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_SIZE;
}

/* Incremental Update */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_NAME        "Incremental Update"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_DESCRIPTION "Incremental update packet indicator (Bit 0)"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_FILTER      "coinbasederivatives.marketdataapi.incrementalupdate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_MASK        0x01

/* Indicative Open Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_NAME        "Indicative Open Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_DESCRIPTION "indicativeOpenPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_FILTER      "coinbasederivatives.marketdataapi.indicativeopenprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_indicative_open_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_indicative_open_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_SIZE;
}

/* Instr Seq Num */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_NAME        "Instr Seq Num"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_DESCRIPTION "instrSeqNum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_FILTER      "coinbasederivatives.marketdataapi.instrseqnum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_instr_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_instr_seq_num, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_SIZE;
}

/* Instrument Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_NAME        "Instrument Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_DESCRIPTION "Total message size in bytes including this header"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_FILTER      "coinbasederivatives.marketdataapi.instrumentflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_SIZE        1

static unsigned
parse_coinbasederivatives_marketdataapi_instrument_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_instrument_flags, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_SIZE;
}

/* Instrument Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_NAME        "Instrument Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_DESCRIPTION "instrumentId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_FILTER      "coinbasederivatives.marketdataapi.instrumentid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_instrument_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_SIZE;
}

/* Instrument Side */
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_NAME        "Instrument Side"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_DESCRIPTION "Instrument Side"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_FILTER      "coinbasederivatives.marketdataapi.instrumentside"
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_SIZE        1

static unsigned
parse_coinbasederivatives_marketdataapi_instrument_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_instrument_side, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_SIZE;
}

/* Is Announced */
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_NAME        "Is Announced"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_DESCRIPTION "isAnnounced"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_FILTER      "coinbasederivatives.marketdataapi.isannounced"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_MASK        0x02

/* Is Call */
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_NAME        "Is Call"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_DESCRIPTION "isCall"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_FILTER      "coinbasederivatives.marketdataapi.iscall"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_MASK        0x04

/* Is Final */
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_NAME        "Is Final"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_DESCRIPTION "isFinal"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_FILTER      "coinbasederivatives.marketdataapi.isfinal"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_MASK        0x01

/* Is Prior Settlement Theoretical */
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_NAME        "Is Prior Settlement Theoretical"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_DESCRIPTION "isPriorSettlementTheoretical"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_FILTER      "coinbasederivatives.marketdataapi.ispriorsettlementtheoretical"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_MASK        0x01

/* Is Strike Delisted */
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_NAME        "Is Strike Delisted"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_DESCRIPTION "isStrikeDelisted"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_FILTER      "coinbasederivatives.marketdataapi.isstrikedelisted"
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_MASK        0x08

/* Large Tick */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_NAME        "Large Tick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_DESCRIPTION "largeTick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_FILTER      "coinbasederivatives.marketdataapi.largetick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_large_tick(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_large_tick, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_SIZE;
}

/* Large Tick Threshold */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_NAME        "Large Tick Threshold"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_DESCRIPTION "largeTickThreshold"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_FILTER      "coinbasederivatives.marketdataapi.largetickthreshold"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_large_tick_threshold, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_SIZE;
}

/* Last Instr Seq Num */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_NAME        "Last Instr Seq Num"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_DESCRIPTION "lastInstrSeqNum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_FILTER      "coinbasederivatives.marketdataapi.lastinstrseqnum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_last_instr_seq_num, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_SIZE;
}

/* Last Trade Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_NAME        "Last Trade Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_DESCRIPTION "lastTradePrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_FILTER      "coinbasederivatives.marketdataapi.lasttradeprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_last_trade_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_last_trade_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_SIZE;
}

/* Last Trade Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_NAME        "Last Trade Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_DESCRIPTION "lastTradeQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_FILTER      "coinbasederivatives.marketdataapi.lasttradeqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_last_trade_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_last_trade_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_SIZE;
}

/* Last Trade Time */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_NAME        "Last Trade Time"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_DESCRIPTION "lastTradeTime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_FILTER      "coinbasederivatives.marketdataapi.lasttradetime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_last_trade_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    if ((int64_t)tvb_get_letoh64(tvb, offset) == INT64_MIN) {
        nstime_t empty = NSTIME_INIT_ZERO;

        proto_tree_add_time_format_value(tree, hf_coinbasederivatives_marketdataapi_last_trade_time, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_SIZE, &empty, "No Value");
    }
    else {
        proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_last_trade_time, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_ENCODING);
    }

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_SIZE;
}

/* Last Trading Session Date */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_NAME        "Last Trading Session Date"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_DESCRIPTION "lastTradingSessionDate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_FILTER      "coinbasederivatives.marketdataapi.lasttradingsessiondate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    nstime_t date = { .secs = (time_t)tvb_get_letohs(tvb, offset) * 86400, .nsecs = 0 };

    proto_tree_add_time(tree, hf_coinbasederivatives_marketdataapi_last_trading_session_date, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_SIZE, &date);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_SIZE;
}

/* Leg 1 Instrument Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_NAME        "Leg 1 Instrument Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_DESCRIPTION "leg1InstrumentId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_FILTER      "coinbasederivatives.marketdataapi.leg1instrumentid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_leg_1_instrument_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_SIZE;
}

/* Leg 2 Instrument Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_NAME        "Leg 2 Instrument Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_DESCRIPTION "leg2InstrumentId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_FILTER      "coinbasederivatives.marketdataapi.leg2instrumentid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_leg_2_instrument_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_SIZE;
}

/* Limit Down Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_NAME        "Limit Down Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_DESCRIPTION "limitDownPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_FILTER      "coinbasederivatives.marketdataapi.limitdownprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_limit_down_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_limit_down_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_SIZE;
}

/* Limit Up Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_NAME        "Limit Up Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_DESCRIPTION "limitUpPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_FILTER      "coinbasederivatives.marketdataapi.limitupprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_limit_up_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_limit_up_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_SIZE;
}

/* Low Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_NAME        "Low Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_DESCRIPTION "lowPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_FILTER      "coinbasederivatives.marketdataapi.lowprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_low_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_low_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_SIZE;
}

/* Match Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_NAME        "Match Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_DESCRIPTION "matchId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_FILTER      "coinbasederivatives.marketdataapi.matchid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_match_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_match_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_SIZE;
}

/* Message Count */
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_NAME        "Message Count"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_DESCRIPTION "messageCount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_FILTER      "coinbasederivatives.marketdataapi.messagecount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_SIZE        1

static unsigned
parse_coinbasederivatives_marketdataapi_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_message_count, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_SIZE;
}

/* Month */
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_NAME        "Month"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_DESCRIPTION "month"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_FILTER      "coinbasederivatives.marketdataapi.month"
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_TYPE        FT_INT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_month, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_SIZE;
}

/* New Leg 1 Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_NAME        "New Leg 1 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_DESCRIPTION "newLeg1Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_FILTER      "coinbasederivatives.marketdataapi.newleg1price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_leg_1_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_leg_1_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_SIZE;
}

/* New Leg 1 Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_NAME        "New Leg 1 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_DESCRIPTION "newLeg1Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.newleg1price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_leg_1_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_leg_1_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_SIZE;
}

/* New Leg 2 Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_NAME        "New Leg 2 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_DESCRIPTION "newLeg2Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_FILTER      "coinbasederivatives.marketdataapi.newleg2price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_leg_2_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_leg_2_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_SIZE;
}

/* New Leg 2 Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_NAME        "New Leg 2 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_DESCRIPTION "newLeg2Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.newleg2price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_leg_2_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_leg_2_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_SIZE;
}

/* New Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_NAME        "New Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_DESCRIPTION "newPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_FILTER      "coinbasederivatives.marketdataapi.newprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_SIZE;
}

/* New Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_NAME        "New Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_DESCRIPTION "newPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.newprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_new_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_new_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_SIZE;
}

/* Next Ask Implied Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_NAME        "Next Ask Implied Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_DESCRIPTION "nextAskImpliedPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_FILTER      "coinbasederivatives.marketdataapi.nextaskimpliedprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_next_ask_implied_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_ask_implied_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_SIZE;
}

/* Next Ask Implied Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_NAME        "Next Ask Implied Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_DESCRIPTION "nextAskImpliedQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_FILTER      "coinbasederivatives.marketdataapi.nextaskimpliedqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_next_ask_implied_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_ask_implied_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_SIZE;
}

/* Next Bid Implied Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_NAME        "Next Bid Implied Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_DESCRIPTION "nextBidImpliedPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_FILTER      "coinbasederivatives.marketdataapi.nextbidimpliedprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_next_bid_implied_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_bid_implied_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_SIZE;
}

/* Next Bid Implied Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_NAME        "Next Bid Implied Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_DESCRIPTION "nextBidImpliedQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_FILTER      "coinbasederivatives.marketdataapi.nextbidimpliedqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_next_bid_implied_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_bid_implied_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_SIZE;
}

/* Next Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_NAME        "Next Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_DESCRIPTION "nextPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_FILTER      "coinbasederivatives.marketdataapi.nextprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_next_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_SIZE;
}

/* Next Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_NAME        "Next Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_DESCRIPTION "nextPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.nextprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_next_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_SIZE;
}

/* Next Qty */
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_NAME        "Next Qty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_DESCRIPTION "nextQty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_FILTER      "coinbasederivatives.marketdataapi.nextqty"
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_next_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_next_qty, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_SIZE;
}

/* Old Contract Size */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_NAME        "Old Contract Size"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_DESCRIPTION "oldContractSize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_FILTER      "coinbasederivatives.marketdataapi.oldcontractsize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_old_contract_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_contract_size, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_SIZE;
}

/* Old Leg 1 Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_NAME        "Old Leg 1 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_DESCRIPTION "oldLeg1Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_FILTER      "coinbasederivatives.marketdataapi.oldleg1price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_leg_1_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_leg_1_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_SIZE;
}

/* Old Leg 1 Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_NAME        "Old Leg 1 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_DESCRIPTION "oldLeg1Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.oldleg1price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_leg_1_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_leg_1_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_SIZE;
}

/* Old Leg 2 Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_NAME        "Old Leg 2 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_DESCRIPTION "oldLeg2Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_FILTER      "coinbasederivatives.marketdataapi.oldleg2price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_leg_2_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_leg_2_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_SIZE;
}

/* Old Leg 2 Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_NAME        "Old Leg 2 Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_DESCRIPTION "oldLeg2Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.oldleg2price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_leg_2_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_leg_2_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_SIZE;
}

/* Old Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_NAME        "Old Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_DESCRIPTION "oldPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_FILTER      "coinbasederivatives.marketdataapi.oldprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_SIZE;
}

/* Old Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_NAME        "Old Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_DESCRIPTION "oldPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.oldprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_old_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_old_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_SIZE;
}

/* Open Interest */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_NAME        "Open Interest"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_DESCRIPTION "openInterest"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_FILTER      "coinbasederivatives.marketdataapi.openinterest"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_open_interest(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_open_interest, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_SIZE;
}

/* Option Expiry Type */
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_NAME        "Option Expiry Type"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_DESCRIPTION "optionExpiryType"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_FILTER      "coinbasederivatives.marketdataapi.optionexpirytype"
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_SIZE        1

static const value_string coinbasederivatives_marketdataapi_option_expiry_type_vals[] = {
    { 0, "Weekly" },
    { 1, "Monthly" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_option_expiry_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_option_expiry_type, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_SIZE;
}

/* Order Count */
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_NAME        "Order Count"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_DESCRIPTION "orderCount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_FILTER      "coinbasederivatives.marketdataapi.ordercount"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_order_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_order_count, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_SIZE;
}

/* Order Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_NAME        "Order Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_DESCRIPTION "orderId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_FILTER      "coinbasederivatives.marketdataapi.orderid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_order_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_SIZE;
}

/* Padding */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_NAME        "Padding"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_DESCRIPTION "Udp sbe alignment padding"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_FILTER      "coinbasederivatives.marketdataapi.padding"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_TYPE        FT_BYTES
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_ENCODING    ENC_NA

/* Predicted Funding Rate */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_NAME        "Predicted Funding Rate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_DESCRIPTION "predictedFundingRate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_FILTER      "coinbasederivatives.marketdataapi.predictedfundingrate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_predicted_funding_rate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_predicted_funding_rate, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_SIZE;
}

/* Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_NAME        "Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_DESCRIPTION "price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_FILTER      "coinbasederivatives.marketdataapi.price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_SIZE;
}

/* Price Increment */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_NAME        "Price Increment"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_DESCRIPTION "priceIncrement"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_FILTER      "coinbasederivatives.marketdataapi.priceincrement"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_price_increment(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_price_increment, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_SIZE;
}

/* Prior Settlement Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_NAME        "Prior Settlement Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_DESCRIPTION "priorSettlementPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_FILTER      "coinbasederivatives.marketdataapi.priorsettlementprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_prior_settlement_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_prior_settlement_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_SIZE;
}

/* Prior Settlement Price V12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_NAME        "Prior Settlement Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_DESCRIPTION "priorSettlementPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_FILTER      "coinbasederivatives.marketdataapi.priorsettlementprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_prior_settlement_price_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_prior_settlement_price_v12, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_SIZE;
}

/* Prior Settlement Price Optional */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_NAME        "Prior Settlement Price Optional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_DESCRIPTION "priorSettlementPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_FILTER      "coinbasederivatives.marketdataapi.priorsettlementpriceoptional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_prior_settlement_price_optional, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_SIZE;
}

/* Product Code */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_NAME        "Product Code"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_DESCRIPTION "productCode"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_FILTER      "coinbasederivatives.marketdataapi.productcode"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_product_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_product_code, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_SIZE;
}

/* Product Group */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_NAME        "Product Group"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_DESCRIPTION "productGroup"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_FILTER      "coinbasederivatives.marketdataapi.productgroup"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_SIZE        1

static const value_string coinbasederivatives_marketdataapi_product_group_vals[] = {
    { 0, "Currency" },
    { 1, "Equity" },
    { 2, "Energy" },
    { 3, "Metals" },
    { 4, "Interest Rate" },
    { 5, "Agriculture" },
    { 6, "Crypto" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_product_group(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_product_group, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_SIZE;
}

/* Product Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_NAME        "Product Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_DESCRIPTION "productId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_FILTER      "coinbasederivatives.marketdataapi.productid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_product_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_product_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_SIZE;
}

/* Quantity */
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_NAME        "Quantity"
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_DESCRIPTION "quantity"
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_FILTER      "coinbasederivatives.marketdataapi.quantity"
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_quantity, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_SIZE;
}

/* Reason */
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_NAME        "Reason"
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_DESCRIPTION "reason"
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_FILTER      "coinbasederivatives.marketdataapi.reason"
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_REASON_SIZE        1

static const value_string coinbasederivatives_marketdataapi_reason_vals[] = {
    { 1, "Seq Too Low" },
    { 2, "Seq Too High" },
    { 3, "Rate Limit Exceeded" },
    { 4, "Other Error" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_reason, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_REASON_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_REASON_SIZE;
}

/* Reserved */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_NAME        "Reserved"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_DESCRIPTION "reserved"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_FILTER      "coinbasederivatives.marketdataapi.reserved"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_TYPE        FT_INT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_reserved(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_reserved, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_SIZE;
}

/* Reserved 11 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_NAME        "Reserved 11"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_DESCRIPTION "11 reserved bits"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_FILTER      "coinbasederivatives.marketdataapi.reserved11"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_MASK        0xFFE0

/* Reserved 12 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_NAME        "Reserved 12"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_DESCRIPTION "12 reserved bits"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_FILTER      "coinbasederivatives.marketdataapi.reserved12"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_MASK        0xFFF0

/* Reserved 13 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_NAME        "Reserved 13"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_DESCRIPTION "13 reserved bits"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_FILTER      "coinbasederivatives.marketdataapi.reserved13"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_MASK        0xFFF8

/* Reserved 15 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_NAME        "Reserved 15"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_DESCRIPTION "15 reserved bits"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_FILTER      "coinbasederivatives.marketdataapi.reserved15"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_MASK        0xFFFE

/* Reserved 7 */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_NAME        "Reserved 7"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_DESCRIPTION "7 reserved bits"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_FILTER      "coinbasederivatives.marketdataapi.reserved7"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_MASK        0xFE

/* Retransmit */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_NAME        "Retransmit"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_DESCRIPTION "Retransmit packet indicator (Bit 2)"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_FILTER      "coinbasederivatives.marketdataapi.retransmit"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_MASK        0x04

/* Retry Delay Nanos */
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_NAME        "Retry Delay Nanos"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_DESCRIPTION "retryDelayNanos"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_FILTER      "coinbasederivatives.marketdataapi.retrydelaynanos"
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_retry_delay_nanos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_retry_delay_nanos, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_SIZE;
}

/* Schema Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_NAME        "Schema Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_DESCRIPTION "Identifier of the schema publishing the message"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_FILTER      "coinbasederivatives.marketdataapi.schemaid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_schema_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_schema_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_SIZE;
}

/* Sell Order Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_NAME        "Sell Order Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_DESCRIPTION "sellOrderId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_FILTER      "coinbasederivatives.marketdataapi.sellorderid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_sell_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_sell_order_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_SIZE;
}

/* Sending Time */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_NAME        "Sending Time"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_DESCRIPTION "Nanoseconds since Unix epoch"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_FILTER      "coinbasederivatives.marketdataapi.sendingtime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_sending_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_sending_time, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_SIZE;
}

/* Seq Num */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_NAME        "Seq Num"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_DESCRIPTION "Sequence number of first message in packet"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_FILTER      "coinbasederivatives.marketdataapi.seqnum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_seq_num, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_SIZE;
}

/* Settlement Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_NAME        "Settlement Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_DESCRIPTION "settlementPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_FILTER      "coinbasederivatives.marketdataapi.settlementprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_settlement_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_settlement_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_SIZE;
}

/* Small Tick */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_NAME        "Small Tick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_DESCRIPTION "smallTick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_FILTER      "coinbasederivatives.marketdataapi.smalltick"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_small_tick(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_small_tick, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_SIZE;
}

/* Snapshot */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_NAME        "Snapshot"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_DESCRIPTION "Snapshot packet indicator (Bit 1)"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_FILTER      "coinbasederivatives.marketdataapi.snapshot"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_DISPLAY     8
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_MASK        0x02

/* Snapshot Instrument Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_NAME        "Snapshot Instrument Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_DESCRIPTION "Instrument id of messages in snapshot packet (not used for incrementals)"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_FILTER      "coinbasederivatives.marketdataapi.snapshotinstrumentid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_snapshot_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_snapshot_instrument_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_SIZE;
}

/* Snapshot Seq Num */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_NAME        "Snapshot Seq Num"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_DESCRIPTION "snapshotSeqNum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_FILTER      "coinbasederivatives.marketdataapi.snapshotseqnum"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_snapshot_seq_num, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_SIZE;
}

/* Spot Mark Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_NAME        "Spot Mark Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_DESCRIPTION "spotMarkPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_FILTER      "coinbasederivatives.marketdataapi.spotmarkprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_spot_mark_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_spot_mark_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_SIZE;
}

/* Spot Mark Price Optional */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_NAME        "Spot Mark Price Optional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_DESCRIPTION "spotMarkPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_FILTER      "coinbasederivatives.marketdataapi.spotmarkpriceoptional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_spot_mark_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_spot_mark_price_optional, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_SIZE;
}

/* Spread Buy Convention */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_NAME        "Spread Buy Convention"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_DESCRIPTION "spreadBuyConvention"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_FILTER      "coinbasederivatives.marketdataapi.spreadbuyconvention"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_SIZE        1

static const value_string coinbasederivatives_marketdataapi_spread_buy_convention_vals[] = {
    { 1, "Use Far Bid" },
    { -1, "Use Near Bid" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_spread_buy_convention, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_SIZE;
}

/* Stat Type */
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_NAME        "Stat Type"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_DESCRIPTION "statType"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_FILTER      "coinbasederivatives.marketdataapi.stattype"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_TYPE        FT_CHAR
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_SIZE        1

static const value_string coinbasederivatives_marketdataapi_stat_type_vals[] = {
    { '4', "Day Opening Price" },
    { '5', "Closing Price" },
    { '6', "Settlement Price" },
    { '7', "Trading Session High Price" },
    { '8', "Trading Session Low Price" },
    { 'F', "Reference Price" },
    { 'I', "Indicative Opening Price" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_stat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_stat_type, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_SIZE;
}

/* Strike Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_NAME        "Strike Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_DESCRIPTION "strikePrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_FILTER      "coinbasederivatives.marketdataapi.strikeprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_strike_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_strike_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_SIZE;
}

/* Symbol */
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_NAME        "Symbol"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_DESCRIPTION "symbol"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_FILTER      "coinbasederivatives.marketdataapi.symbol"
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_TYPE        FT_STRING
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_SIZE        24

static unsigned
parse_coinbasederivatives_marketdataapi_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_symbol, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_SIZE;
}

/* Template Id values the dispatch switches on */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION        10
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION          11
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION          12
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE                 17
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT                             20
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE                          21
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE                  22
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY                         33
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE                                 30
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND                           31
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND                    34
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST                            32
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT                           40
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME                  41
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST                         42
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FUNDING_RATE                          43
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT 110
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT   111
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT   112
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT                        120
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT                       122
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE                          124
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST                    200
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT                     202

/* Template Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_NAME        "Template Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_DESCRIPTION "Template ID used to encode the message"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FILTER      "coinbasederivatives.marketdataapi.templateid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SIZE        2

static const value_string coinbasederivatives_marketdataapi_template_id_vals[] = {
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION, "Outright Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION, "Spread Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION, "Option Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT, "Order Put Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE, "Order Delete Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE, "Implied Order Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND, "Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND, "Spread Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST, "Trade Bust Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT, "Market Stat Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME, "Trade Session Volume Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST, "Open Interest Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FUNDING_RATE, "Funding Rate Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT, "Start Of Outright Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT, "Start Of Spread Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT, "Start Of Option Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT, "Order Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT, "End Of Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_template_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_template_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SIZE;
}

/* Tick Size */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_NAME        "Tick Size"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_DESCRIPTION "tickSize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_FILTER      "coinbasederivatives.marketdataapi.ticksize"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_tick_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_tick_size, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_SIZE;
}

/* Trade Volume */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_NAME        "Trade Volume"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_DESCRIPTION "tradeVolume"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_FILTER      "coinbasederivatives.marketdataapi.tradevolume"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_trade_volume(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_trade_volume, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_SIZE;
}

/* Trading Session Date */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_NAME        "Trading Session Date"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_DESCRIPTION "tradingSessionDate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_FILTER      "coinbasederivatives.marketdataapi.tradingsessiondate"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_trading_session_date(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    nstime_t date = { .secs = (time_t)tvb_get_letohs(tvb, offset) * 86400, .nsecs = 0 };

    proto_tree_add_time(tree, hf_coinbasederivatives_marketdataapi_trading_session_date, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_SIZE, &date);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_SIZE;
}

/* Trading Status */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_NAME        "Trading Status"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_DESCRIPTION "tradingStatus"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_FILTER      "coinbasederivatives.marketdataapi.tradingstatus"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_TYPE        FT_INT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_SIZE        1

static const value_string coinbasederivatives_marketdataapi_trading_status_vals[] = {
    { 0, "Pre Open" },
    { 1, "Open" },
    { 2, "Halt" },
    { 3, "Pause" },
    { 4, "Close" },
    { 5, "Pre Open No Cancel" },
    { 6, "Expired" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_marketdataapi_trading_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_trading_status, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_SIZE;
}

/* Transact Time */
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_NAME        "Transact Time"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_DESCRIPTION "transactTime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_FILTER      "coinbasederivatives.marketdataapi.transacttime"
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_transact_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_transact_time, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_SIZE;
}

/* Underlying Instrument Id */
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_NAME        "Underlying Instrument Id"
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_DESCRIPTION "underlyingInstrumentId"
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_FILTER      "coinbasederivatives.marketdataapi.underlyinginstrumentid"
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_underlying_instrument_id, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_SIZE;
}

/* Version */
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_NAME        "Version"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_DESCRIPTION "Schema version"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_FILTER      "coinbasederivatives.marketdataapi.version"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_version, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_SIZE;
}

/* Vwap Price */
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_NAME        "Vwap Price"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_DESCRIPTION "vwapPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_FILTER      "coinbasederivatives.marketdataapi.vwapprice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_vwap_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_vwap_price, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_SIZE;
}

/* Vwap Price Optional */
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_NAME        "Vwap Price Optional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_DESCRIPTION "vwapPrice"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_FILTER      "coinbasederivatives.marketdataapi.vwappriceoptional"
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_marketdataapi_vwap_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_vwap_price_optional, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_SIZE;
}

/* Week Of Month */
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_NAME        "Week Of Month"
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_DESCRIPTION "weekOfMonth"
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_FILTER      "coinbasederivatives.marketdataapi.weekofmonth"
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_TYPE        FT_INT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_week_of_month(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_week_of_month, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_SIZE;
}

/* Year */
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_NAME        "Year"
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_DESCRIPTION "year"
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_FILTER      "coinbasederivatives.marketdataapi.year"
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_TYPE        FT_INT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_SIZE        2

static unsigned
parse_coinbasederivatives_marketdataapi_year(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_marketdataapi_year, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_SIZE, COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_SIZE;
}

/*
 * CoinbaseDerivatives MarketDataApi Structs
 */

/* Packet Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_NAME        "Packet Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_DESCRIPTION "Uint8 bit set carrying the packet type (INCREMENTAL_UPDATE / SNAPSHOT / RETRANSMIT)"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_FILTER      "coinbasederivatives.marketdataapi.packetflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_SIZE        1

static int * const coinbasederivatives_marketdataapi_packet_flags_fields[] = {
    &hf_coinbasederivatives_marketdataapi_retransmit,
    &hf_coinbasederivatives_marketdataapi_snapshot,
    &hf_coinbasederivatives_marketdataapi_incremental_update,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_packet_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_packet_flags,
        ett_coinbasederivatives_marketdataapi_packet_flags, coinbasederivatives_marketdataapi_packet_flags_fields, COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_SIZE;
}

/* Definition Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_NAME        "Definition Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_DESCRIPTION "InstrumentDefinitionFlags bit set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_FILTER      "coinbasederivatives.marketdataapi.definitionflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_SIZE        2

static int * const coinbasederivatives_marketdataapi_definition_flags_fields[] = {
    &hf_coinbasederivatives_marketdataapi_reserved_11,
    &hf_coinbasederivatives_marketdataapi_funding_rate_applicable,
    &hf_coinbasederivatives_marketdataapi_is_strike_delisted,
    &hf_coinbasederivatives_marketdataapi_is_call,
    &hf_coinbasederivatives_marketdataapi_is_announced,
    &hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_definition_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_definition_flags,
        ett_coinbasederivatives_marketdataapi_definition_flags, coinbasederivatives_marketdataapi_definition_flags_fields, COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_SIZE;
}

/* Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_NAME        "Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_DESCRIPTION "FundingRateFlags bit set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_FILTER      "coinbasederivatives.marketdataapi.flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_SIZE        1

static int * const coinbasederivatives_marketdataapi_flags_fields[] = {
    &hf_coinbasederivatives_marketdataapi_reserved_7,
    &hf_coinbasederivatives_marketdataapi_is_final,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_flags,
        ett_coinbasederivatives_marketdataapi_flags, coinbasederivatives_marketdataapi_flags_fields, COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_SIZE;
}

/* Definition Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_NAME        "Definition Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_DESCRIPTION "InstrumentDefinitionFlags bit set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_FILTER      "coinbasederivatives.marketdataapi.definitionflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_SIZE        2

static int * const coinbasederivatives_marketdataapi_definition_flags_v17_fields[] = {
    &hf_coinbasederivatives_marketdataapi_reserved_12,
    &hf_coinbasederivatives_marketdataapi_is_strike_delisted,
    &hf_coinbasederivatives_marketdataapi_is_call,
    &hf_coinbasederivatives_marketdataapi_is_announced,
    &hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_definition_flags_v17,
        ett_coinbasederivatives_marketdataapi_definition_flags_v17, coinbasederivatives_marketdataapi_definition_flags_v17_fields, COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_SIZE;
}

/* Definition Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_NAME        "Definition Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_DESCRIPTION "InstrumentDefinitionFlags bit set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_FILTER      "coinbasederivatives.marketdataapi.definitionflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_SIZE        2

static int * const coinbasederivatives_marketdataapi_definition_flags_v13_fields[] = {
    &hf_coinbasederivatives_marketdataapi_reserved_13,
    &hf_coinbasederivatives_marketdataapi_is_call,
    &hf_coinbasederivatives_marketdataapi_is_announced,
    &hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_definition_flags_v13,
        ett_coinbasederivatives_marketdataapi_definition_flags_v13, coinbasederivatives_marketdataapi_definition_flags_v13_fields, COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_SIZE;
}

/* Definition Flags */
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_NAME        "Definition Flags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_DESCRIPTION "InstrumentDefinitionFlags bit set"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_FILTER      "coinbasederivatives.marketdataapi.definitionflags"
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_MASK        0x0
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_SIZE        2

static int * const coinbasederivatives_marketdataapi_definition_flags_v12_fields[] = {
    &hf_coinbasederivatives_marketdataapi_reserved_15,
    &hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical,
    NULL
};

static unsigned
parse_coinbasederivatives_marketdataapi_definition_flags_v12(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_marketdataapi_definition_flags_v12,
        ett_coinbasederivatives_marketdataapi_definition_flags_v12, coinbasederivatives_marketdataapi_definition_flags_v12_fields, COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_ENCODING);

    return offset + COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_coinbasederivatives_marketdataapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_outright_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_instr_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_logical_expiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_option_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trading_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_order_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_implied_order_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_summary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_amend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_trade_amend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_bust(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_market_stat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_open_interest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_funding_rate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_order_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_end_of_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_end_of_cycle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_retransmit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_implied_order_update_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_summary_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_trade_amend_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_spread_trade_amend_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_marketdataapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_marketdataapi_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_marketdataapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_marketdataapi_payload_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);

/* Message Header */
static unsigned
dissect_coinbasederivatives_marketdataapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_marketdataapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_marketdataapi_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_marketdataapi_frame_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_block_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_template_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_schema_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_version(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Outright Instrument Definition Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_outright_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_funding_interval_minutes(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_fair_value_limit(tvb, pinfo, tree, offset);

    return offset;
}

/* Instr Header */
static unsigned
dissect_coinbasederivatives_marketdataapi_instr_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_marketdataapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_marketdataapi_instr_header, &item, "Instr Header");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_marketdataapi_instrument_flags(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_instrument_side(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_instr_seq_num(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_reserved(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_transact_time(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Logical Expiry */
static unsigned
dissect_coinbasederivatives_marketdataapi_logical_expiry(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_marketdataapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_marketdataapi_logical_expiry, &item, "Logical Expiry");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_marketdataapi_year(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_month(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_week_of_month(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_marketdataapi_day_of_month(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Spread Instrument Definition Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Option Instrument Definition Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_option_instrument_definition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_option_expiry_type(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Trading Status Update Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trading_status_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Put Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_order_put(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Implied Order Update Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_implied_order_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_qty(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Summary Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_summary(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_aggressor_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_aggressor_receive_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_deepest_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Amend Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_amend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Trade Amend Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_trade_amend(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_leg_1_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_leg_1_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_leg_2_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_leg_2_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Bust Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_bust(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Stat Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_market_stat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_stat_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Session Volume Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trade_volume(tvb, pinfo, tree, offset);

    return offset;
}

/* Open Interest Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_open_interest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Funding Rate Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_funding_rate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_funding_rate(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_futures_mark_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spot_mark_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_fair_value(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_final_funding_rate_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_flags(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Outright Instrument Snapshot Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_funding_interval_minutes(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_fair_value_limit(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Spread Instrument Snapshot Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Option Instrument Snapshot Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_option_expiry_type(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Snapshot Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_order_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_transact_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Snapshot Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_end_of_snapshot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trade_volume(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_indicative_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_day_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_close_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_low_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_high_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_final_funding_rate(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_final_futures_mark_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_final_funding_rate_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_futures_mark_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_predicted_funding_rate(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spot_mark_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_fair_value_optional(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Cycle Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_end_of_cycle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_active_instrument_count(tvb, pinfo, tree, offset);

    return offset;
}

/* Retransmit Request Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_retransmit_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_begin_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_message_count(tvb, pinfo, tree, offset);

    return offset;
}

/* Retransmit Reject Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_retry_delay_nanos(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_details(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Outright Instrument Definition Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Instrument Definition Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Option Instrument Definition Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_option_expiry_type(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Outright Instrument Snapshot Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_tick_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_contract_size(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Option Instrument Snapshot Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_option_expiry_type(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_marketdataapi_logical_expiry(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Snapshot Message V17 */
static unsigned
dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trade_volume(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_indicative_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_day_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_close_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_low_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_high_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v17(tvb, pinfo, tree, offset);

    return offset;
}

/* Outright Instrument Definition Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Instrument Definition Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvb, pinfo, tree, offset);

    return offset;
}

/* Option Instrument Definition Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Outright Instrument Snapshot Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Spread Instrument Snapshot Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Option Instrument Snapshot Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_small_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_large_tick_threshold(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_strike_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_underlying_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Snapshot Message V13 */
static unsigned
dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trade_volume(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_indicative_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_day_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_close_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_low_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_high_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v13(tvb, pinfo, tree, offset);

    return offset;
}

/* Outright Instrument Definition Message V12 */
static unsigned
dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v12(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Instrument Definition Message V12 */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v12(tvb, pinfo, tree, offset);

    return offset;
}

/* Implied Order Update Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_implied_order_update_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_qty(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Summary Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_summary_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_aggressor_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_aggressor_receive_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_deepest_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Amend Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_trade_amend_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_price_v12(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Trade Amend Message */
static unsigned
dissect_coinbasederivatives_marketdataapi_spread_trade_amend_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_coinbasederivatives_marketdataapi_instr_header(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_buy_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_sell_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_leg_1_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_leg_1_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_old_leg_2_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_new_leg_2_price_v12(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Outright Instrument Snapshot Message V12 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);

    return offset;
}

/* Start Of Spread Instrument Snapshot Message V12 */
static unsigned
dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_instr_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_symbol(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_description(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_price_increment(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_cfi_code(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_currency(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_contract_size_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_order_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_first_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_session_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_product_group(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trading_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_1_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_leg_2_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_spread_buy_convention(tvb, pinfo, tree, offset);

    return offset;
}

/* End Of Snapshot Message V12 */
static unsigned
dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_marketdataapi_snapshot_seq_num(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_trade_volume(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_indicative_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_day_open_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_close_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_low_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_high_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_vwap_price_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_settlement_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_down_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_limit_up_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_last_trade_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_best_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_bid_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_next_ask_implied_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_prior_settlement_price_v12(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_marketdataapi_definition_flags_v12(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * CoinbaseDerivatives MarketDataApi Parse Trees, a dispatch per distinct branch definition
 */

static const value_string coinbasederivatives_marketdataapi_messages[] = {
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION, "Outright Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION, "Spread Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION, "Option Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT, "Order Put Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE, "Order Delete Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE, "Implied Order Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND, "Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND, "Spread Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST, "Trade Bust Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT, "Market Stat Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME, "Trade Session Volume Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST, "Open Interest Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FUNDING_RATE, "Funding Rate Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT, "Start Of Outright Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT, "Start Of Spread Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT, "Start Of Option Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT, "Order Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT, "End Of Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_marketdataapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_marketdataapi_messages, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_outright_instrument_definition(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_spread_instrument_definition(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_option_instrument_definition(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_trading_status_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT:
        return dissect_coinbasederivatives_marketdataapi_order_put(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE:
        return dissect_coinbasederivatives_marketdataapi_order_delete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_implied_order_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_coinbasederivatives_marketdataapi_trade_summary(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_coinbasederivatives_marketdataapi_trade(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_spread_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST:
        return dissect_coinbasederivatives_marketdataapi_trade_bust(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT:
        return dissect_coinbasederivatives_marketdataapi_market_stat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME:
        return dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST:
        return dissect_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FUNDING_RATE:
        return dissect_coinbasederivatives_marketdataapi_funding_rate(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_order_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_end_of_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return dissect_coinbasederivatives_marketdataapi_end_of_cycle(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_coinbasederivatives_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_marketdataapi_messages_v17[] = {
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION, "Outright Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION, "Spread Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION, "Option Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT, "Order Put Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE, "Order Delete Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE, "Implied Order Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND, "Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND, "Spread Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST, "Trade Bust Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT, "Market Stat Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME, "Trade Session Volume Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST, "Open Interest Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT, "Start Of Outright Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT, "Start Of Spread Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT, "Start Of Option Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT, "Order Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT, "End Of Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE, "End Of Cycle Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_marketdataapi_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_marketdataapi_messages_v17, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_trading_status_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT:
        return dissect_coinbasederivatives_marketdataapi_order_put(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE:
        return dissect_coinbasederivatives_marketdataapi_order_delete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_implied_order_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_coinbasederivatives_marketdataapi_trade_summary(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_coinbasederivatives_marketdataapi_trade(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_spread_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST:
        return dissect_coinbasederivatives_marketdataapi_trade_bust(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT:
        return dissect_coinbasederivatives_marketdataapi_market_stat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME:
        return dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST:
        return dissect_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_order_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return dissect_coinbasederivatives_marketdataapi_end_of_cycle(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_coinbasederivatives_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_marketdataapi_messages_v13[] = {
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION, "Outright Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION, "Spread Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION, "Option Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT, "Order Put Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE, "Order Delete Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE, "Implied Order Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND, "Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND, "Spread Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST, "Trade Bust Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT, "Market Stat Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME, "Trade Session Volume Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST, "Open Interest Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT, "Start Of Outright Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT, "Start Of Spread Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT, "Start Of Option Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT, "Order Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT, "End Of Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_marketdataapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_marketdataapi_messages_v13, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_option_instrument_definition_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_trading_status_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT:
        return dissect_coinbasederivatives_marketdataapi_order_put(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE:
        return dissect_coinbasederivatives_marketdataapi_order_delete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_implied_order_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_coinbasederivatives_marketdataapi_trade_summary(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_coinbasederivatives_marketdataapi_trade(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_spread_trade_amend(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST:
        return dissect_coinbasederivatives_marketdataapi_trade_bust(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT:
        return dissect_coinbasederivatives_marketdataapi_market_stat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME:
        return dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST:
        return dissect_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_option_instrument_snapshot_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_order_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_coinbasederivatives_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_marketdataapi_messages_v12[] = {
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION, "Outright Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION, "Spread Instrument Definition Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE, "Trading Status Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT, "Order Put Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE, "Order Delete Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE, "Implied Order Update Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY, "Trade Summary Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE, "Trade Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND, "Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND, "Spread Trade Amend Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST, "Trade Bust Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT, "Market Stat Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME, "Trade Session Volume Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST, "Open Interest Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT, "Start Of Outright Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT, "Start Of Spread Instrument Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT, "Order Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT, "End Of Snapshot Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST, "Retransmit Request Message" },
    { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT, "Retransmit Reject Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_marketdataapi_payload_v12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_marketdataapi_messages_v12, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_outright_instrument_definition_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION:
        return dissect_coinbasederivatives_marketdataapi_spread_instrument_definition_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_trading_status_update(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT:
        return dissect_coinbasederivatives_marketdataapi_order_put(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE:
        return dissect_coinbasederivatives_marketdataapi_order_delete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE:
        return dissect_coinbasederivatives_marketdataapi_implied_order_update_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return dissect_coinbasederivatives_marketdataapi_trade_summary_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return dissect_coinbasederivatives_marketdataapi_trade(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_trade_amend_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND:
        return dissect_coinbasederivatives_marketdataapi_spread_trade_amend_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST:
        return dissect_coinbasederivatives_marketdataapi_trade_bust(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT:
        return dissect_coinbasederivatives_marketdataapi_market_stat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME:
        return dissect_coinbasederivatives_marketdataapi_trade_session_volume(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST:
        return dissect_coinbasederivatives_marketdataapi_open_interest(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_outright_instrument_snapshot_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_start_of_spread_instrument_snapshot_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_order_snapshot(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT:
        return dissect_coinbasederivatives_marketdataapi_end_of_snapshot_v12(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return dissect_coinbasederivatives_marketdataapi_retransmit_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return dissect_coinbasederivatives_marketdataapi_retransmit_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
coinbasederivatives_marketdataapi_show(uint32_t template_id)
{
    switch (template_id) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OUTRIGHT_INSTRUMENT_DEFINITION:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_INSTRUMENT_DEFINITION:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPTION_INSTRUMENT_DEFINITION:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADING_STATUS_UPDATE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_PUT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_DELETE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_IMPLIED_ORDER_UPDATE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SUMMARY:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_AMEND:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_SPREAD_TRADE_AMEND:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_BUST:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MARKET_STAT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TRADE_SESSION_VOLUME:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_OPEN_INTEREST:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FUNDING_RATE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OUTRIGHT_INSTRUMENT_SNAPSHOT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_SPREAD_INSTRUMENT_SNAPSHOT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_START_OF_OPTION_INSTRUMENT_SNAPSHOT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_ORDER_SNAPSHOT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_SNAPSHOT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_END_OF_CYCLE:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REQUEST:
        return coinbasederivatives_marketdataapi_show_application_messages;
    case COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_RETRANSMIT_REJECT:
        return coinbasederivatives_marketdataapi_show_application_messages;
    }

    return true;
}

typedef struct coinbasederivatives_marketdataapi_parse coinbasederivatives_marketdataapi_parse;

struct coinbasederivatives_marketdataapi_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
};

static const coinbasederivatives_marketdataapi_parse coinbasederivatives_marketdataapi_parse_v19 = { coinbasederivatives_marketdataapi_messages, dissect_coinbasederivatives_marketdataapi_payload };
static const coinbasederivatives_marketdataapi_parse coinbasederivatives_marketdataapi_parse_v17 = { coinbasederivatives_marketdataapi_messages_v17, dissect_coinbasederivatives_marketdataapi_payload_v17 };
static const coinbasederivatives_marketdataapi_parse coinbasederivatives_marketdataapi_parse_v13 = { coinbasederivatives_marketdataapi_messages_v13, dissect_coinbasederivatives_marketdataapi_payload_v13 };
static const coinbasederivatives_marketdataapi_parse coinbasederivatives_marketdataapi_parse_v12 = { coinbasederivatives_marketdataapi_messages_v12, dissect_coinbasederivatives_marketdataapi_payload_v12 };

/* Parse tree of the selected version */
static const coinbasederivatives_marketdataapi_parse *
coinbasederivatives_marketdataapi_parse_for(int version)
{
    switch (version) {
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_7:
        return &coinbasederivatives_marketdataapi_parse_v17;
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_3:
        return &coinbasederivatives_marketdataapi_parse_v13;
    case COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_1_2:
        return &coinbasederivatives_marketdataapi_parse_v12;
    default:
        return &coinbasederivatives_marketdataapi_parse_v19;
    }
}

/* Packet Header */
static unsigned
dissect_coinbasederivatives_marketdataapi_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, COINBASEDERIVATIVES_MARKETDATAAPI_HEADER_SIZE,
        ett_coinbasederivatives_marketdataapi_header, NULL, "Packet Header");

    offset = parse_coinbasederivatives_marketdataapi_sending_time(tvb, pinfo, header, offset);
    offset = parse_coinbasederivatives_marketdataapi_seq_num(tvb, pinfo, header, offset);
    offset = parse_coinbasederivatives_marketdataapi_channel_id(tvb, pinfo, header, offset);
    offset = parse_coinbasederivatives_marketdataapi_packet_flags(tvb, pinfo, header, offset);
    offset = parse_coinbasederivatives_marketdataapi_message_count(tvb, pinfo, header, offset);
    offset = parse_coinbasederivatives_marketdataapi_snapshot_instrument_id(tvb, pinfo, header, offset);

    return offset;
}

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_coinbasederivatives_marketdataapi_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const coinbasederivatives_marketdataapi_parse *parse)
{
    uint32_t frame_length = tvb_get_letohs(tvb, offset);
    uint32_t template_id = tvb_get_letohs(tvb, offset + 4);

    const char *name = val_to_str(pinfo->pool, template_id, parse->messages, "Unknown (%u)");

    proto_tree *message = coinbasederivatives_marketdataapi_show(template_id)
        ? proto_tree_add_subtree(tree, tvb, offset, frame_length, ett_coinbasederivatives_marketdataapi_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_coinbasederivatives_marketdataapi_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, template_id);

    /* Padding: Udp sbe alignment padding */
    uint32_t padding = frame_length - (uint32_t)(position - offset);

    if (padding > 0) {
        proto_tree_add_item(message, hf_coinbasederivatives_marketdataapi_padding, tvb, position, padding, COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_ENCODING);
        position += padding;
    }

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + frame_length) {
        expert_add_info(pinfo, message, &ei_coinbasederivatives_marketdataapi_length);
    }

    return frame_length;
}

/* Messages to the end of the payload, returns the position after the last message */
static unsigned
dissect_coinbasederivatives_marketdataapi_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const coinbasederivatives_marketdataapi_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        offset += dissect_coinbasederivatives_marketdataapi_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_coinbasederivatives_marketdataapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_coinbasederivatives_marketdataapi, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_coinbasederivatives_marketdataapi);

    uint64_t seconds = tvb_get_letoh64(tvb, 0) / UINT64_C(1000000000);
    int declared = tvb_captured_length(tvb) >= 34
        ? (int)tvb_get_letohs(tvb, 32)
        : -1;
    int version = coinbasederivatives_marketdataapi_version(seconds, declared);

    proto_item_append_text(item, " %s", coinbasederivatives_marketdataapi_version_name(version));

    const coinbasederivatives_marketdataapi_parse *parse = coinbasederivatives_marketdataapi_parse_for(version);
    unsigned position = dissect_coinbasederivatives_marketdataapi_header(tvb, pinfo, packet, 0);

    position = dissect_coinbasederivatives_marketdataapi_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define COINBASEDERIVATIVES_MARKETDATAAPI_MINIMUM_SIZE 24

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
coinbasederivatives_marketdataapi_heur_port(packet_info *pinfo)
{
    return value_is_in_range(coinbasederivatives_marketdataapi_pref_ports, pinfo->destport);
}

/* Does the frame pass every test of Packet? */
static bool
coinbasederivatives_marketdataapi_heur_accepts(tvbuff_t *tvb _U_, packet_info *pinfo)
{
    if (!coinbasederivatives_marketdataapi_heur_port(pinfo)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on */
static bool
dissect_coinbasederivatives_marketdataapi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < COINBASEDERIVATIVES_MARKETDATAAPI_MINIMUM_SIZE) {
        return false;
    }

    if (!coinbasederivatives_marketdataapi_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_coinbasederivatives_marketdataapi(tvb, pinfo, tree, data);

    return true;
}

/*
 * CoinbaseDerivatives MarketDataApi Registration
 */

void
proto_register_coinbasederivatives_marketdataapi(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_coinbasederivatives_marketdataapi_active_instrument_count,
            { COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_ACTIVE_INSTRUMENT_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_aggressor_order_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_aggressor_receive_time,
            { COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_AGGRESSOR_RECEIVE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_begin_seq_num,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEGIN_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_ask_implied_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_ask_implied_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_ASK_IMPLIED_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_bid_implied_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_bid_implied_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_BID_IMPLIED_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_best_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BEST_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_block_length,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_buy_order_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_BUY_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_cfi_code,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CFI_CODE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_channel_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CHANNEL_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_close_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CLOSE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_contract_size,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_contract_size_v13,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CONTRACT_SIZE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_correlation_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CORRELATION_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_currency,
            { COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_CURRENCY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_day_of_month,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OF_MONTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_day_open_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DAY_OPEN_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_deepest_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_deepest_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEEPEST_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_description,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DESCRIPTION_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_details,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DETAILS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_fair_value,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_fair_value_limit,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_LIMIT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_fair_value_optional,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FAIR_VALUE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_final_funding_rate,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_final_funding_rate_timestamp,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUNDING_RATE_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_final_futures_mark_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FINAL_FUTURES_MARK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_first_trading_session_date,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FIRST_TRADING_SESSION_DATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_frame_length,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FRAME_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_funding_interval_minutes,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_INTERVAL_MINUTES_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_funding_rate,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_futures_mark_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_futures_mark_price_optional,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUTURES_MARK_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_high_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_HIGH_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_indicative_open_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INDICATIVE_OPEN_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_instr_seq_num,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTR_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_instrument_flags,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_instrument_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_instrument_side,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INSTRUMENT_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_large_tick,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_large_tick_threshold,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LARGE_TICK_THRESHOLD_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_last_instr_seq_num,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_INSTR_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_last_trade_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_last_trade_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_last_trade_time,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_last_trading_session_date,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LAST_TRADING_SESSION_DATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_leg_1_instrument_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_1_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_leg_2_instrument_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LEG_2_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_limit_down_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_DOWN_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_limit_up_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LIMIT_UP_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_low_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_LOW_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_match_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_MATCH_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_message_count,
            { COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_month,
            { COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_MONTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_leg_1_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_leg_1_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_1_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_leg_2_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_leg_2_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_LEG_2_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_new_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEW_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_ask_implied_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_ask_implied_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_ASK_IMPLIED_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_bid_implied_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_bid_implied_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_BID_IMPLIED_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_next_qty,
            { COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_NEXT_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_contract_size,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_CONTRACT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_leg_1_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_leg_1_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_1_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_leg_2_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_leg_2_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_LEG_2_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_old_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OLD_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_open_interest,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_32),
              COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPEN_INTEREST_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_option_expiry_type,
            { COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_option_expiry_type_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_OPTION_EXPIRY_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_order_count,
            { COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_order_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_padding,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PADDING_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_predicted_funding_rate,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PREDICTED_FUNDING_RATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_price_increment,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRICE_INCREMENT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_prior_settlement_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_prior_settlement_price_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_V12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_prior_settlement_price_optional,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRIOR_SETTLEMENT_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_product_code,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_CODE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_product_group,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_product_group_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_GROUP_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_product_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PRODUCT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_quantity,
            { COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reason,
            { COINBASEDERIVATIVES_MARKETDATAAPI_REASON_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_REASON_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_REASON_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_REASON_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_reason_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_REASON_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_retry_delay_nanos,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRY_DELAY_NANOS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_schema_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SCHEMA_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_sell_order_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_nullable_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SELL_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_sending_time,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SENDING_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_seq_num,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_settlement_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SETTLEMENT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_small_tick,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SMALL_TICK_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_snapshot_instrument_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_snapshot_seq_num,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_spot_mark_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_spot_mark_price_optional,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPOT_MARK_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_spread_buy_convention,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_spread_buy_convention_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SPREAD_BUY_CONVENTION_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_stat_type,
            { COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_stat_type_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_STAT_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_strike_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_STRIKE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_symbol,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_template_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_template_id_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TEMPLATE_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_tick_size,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TICK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_trade_volume,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADE_VOLUME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_trading_session_date,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_SESSION_DATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_trading_status,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_DISPLAY,
              VALS(coinbasederivatives_marketdataapi_trading_status_vals),
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRADING_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_transact_time,
            { COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_TRANSACT_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_underlying_instrument_id,
            { COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_UNDERLYING_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_version,
            { COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_vwap_price,
            { COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64),
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_vwap_price_optional,
            { COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_marketdataapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_VWAP_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_week_of_month,
            { COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_WEEK_OF_MONTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_year,
            { COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_YEAR_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_coinbasederivatives_marketdataapi_funding_rate_applicable,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FUNDING_RATE_APPLICABLE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_incremental_update,
            { COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_INCREMENTAL_UPDATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_is_announced,
            { COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_ANNOUNCED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_is_call,
            { COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_CALL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_is_final,
            { COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_FINAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_is_prior_settlement_theoretical,
            { COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_PRIOR_SETTLEMENT_THEORETICAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_is_strike_delisted,
            { COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_IS_STRIKE_DELISTED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved_11,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_11_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved_12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_12_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved_13,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved_15,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_15_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_reserved_7,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RESERVED_7_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_retransmit,
            { COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_RETRANSMIT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_snapshot,
            { COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_SNAPSHOT_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_coinbasederivatives_marketdataapi_packet_flags,
            { COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_PACKET_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_definition_flags,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_flags,
            { COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_definition_flags_v17,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V17_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_definition_flags_v13,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_marketdataapi_definition_flags_v12,
            { COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_NAME,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_TYPE,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_MASK,
              COINBASEDERIVATIVES_MARKETDATAAPI_DEFINITION_FLAGS_V12_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_coinbasederivatives_marketdataapi,
        &ett_coinbasederivatives_marketdataapi_header,
        &ett_coinbasederivatives_marketdataapi_message,
        &ett_coinbasederivatives_marketdataapi_packet_flags,
        &ett_coinbasederivatives_marketdataapi_definition_flags,
        &ett_coinbasederivatives_marketdataapi_flags,
        &ett_coinbasederivatives_marketdataapi_definition_flags_v17,
        &ett_coinbasederivatives_marketdataapi_definition_flags_v13,
        &ett_coinbasederivatives_marketdataapi_definition_flags_v12,
        &ett_coinbasederivatives_marketdataapi_message_header,
        &ett_coinbasederivatives_marketdataapi_instr_header,
        &ett_coinbasederivatives_marketdataapi_logical_expiry,
    };

    static ei_register_info ei[] = {
        { &ei_coinbasederivatives_marketdataapi_length,
            { COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_FILTER,
              COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_GROUP,
              COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_SEVERITY,
              COINBASEDERIVATIVES_MARKETDATAAPI_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_coinbasederivatives_marketdataapi = proto_register_protocol(COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_NAME, COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_SHORT, COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_FILTER);

    proto_register_field_array(proto_coinbasederivatives_marketdataapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_coinbasederivatives_marketdataapi = expert_register_protocol(proto_coinbasederivatives_marketdataapi);
    expert_register_field_array(expert_coinbasederivatives_marketdataapi, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_coinbasederivatives_marketdataapi, NULL);

    prefs_register_enum_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_VERSION_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_marketdataapi_pref_version,
        coinbasederivatives_marketdataapi_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_marketdataapi_show_headers);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_marketdataapi_show_application_messages);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_marketdataapi_show_structs);

    prefs_register_uint_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &coinbasederivatives_marketdataapi_pref_decimal_places);

    range_convert_str(
        wmem_epan_scope(),
        &coinbasederivatives_marketdataapi_pref_ports,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_DEFAULT,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_NAME,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_marketdataapi_pref_ports,
        COINBASEDERIVATIVES_MARKETDATAAPI_PORTS_PREFERENCE_MAXIMUM);

    coinbasederivatives_marketdataapi_handle = register_dissector(COINBASEDERIVATIVES_MARKETDATAAPI_PROTOCOL_FILTER, dissect_coinbasederivatives_marketdataapi, proto_coinbasederivatives_marketdataapi);
}

void
proto_reg_handoff_coinbasederivatives_marketdataapi(void)
{
    heur_dissector_add("udp", dissect_coinbasederivatives_marketdataapi_heur, "CoinbaseDerivatives MarketDataApi over UDP",
        "coinbasederivatives_marketdataapi_udp", proto_coinbasederivatives_marketdataapi, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("udp.port", coinbasederivatives_marketdataapi_handle);
}
