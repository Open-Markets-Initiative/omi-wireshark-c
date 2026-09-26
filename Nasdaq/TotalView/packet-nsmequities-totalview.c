/* packet-nsmequities-totalview.c
 * Routines for Nasdaq TotalView Itch dissection
 *
 * Aggregated protocol versions: 5.0.2026, 5.0.2023, 5.0.2022, 5.0.2018, 5.0.2017, 4.1, 3.2, 4.0, 3.1, 3.1.f, 4.0.f, 3.0, 2.0.a, 2.0, 1.0
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Nasdaq.NsmEquities.TotalView.Itch.v5.0.2026
 *   Nasdaq.NsmEquities.TotalView.Itch.v5.0.2023
 *   Nasdaq.NsmEquities.TotalView.Itch.v5.0.2022
 *   Nasdaq.NsmEquities.TotalView.Itch.v5.0.2018
 *   Nasdaq.NsmEquities.TotalView.Itch.v5.0.2017
 *   Nasdaq.NsmEquities.TotalView.Itch.v4.1
 *   Nasdaq.NsmEquities.TotalView.Itch.v3.2
 *   Nasdaq.NsmEquities.TotalView.Itch.v4.0
 *   Nasdaq.NsmEquities.TotalView.Itch.v3.1
 *   Nasdaq.NsmEquities.TotalView.Itch.v3.1.f
 *   Nasdaq.NsmEquities.TotalView.Itch.v4.0.f
 *   Nasdaq.NsmEquities.TotalView.Itch.v3.0
 *   Nasdaq.NsmEquities.TotalView.Itch.v2.0.a
 *   Nasdaq.NsmEquities.TotalView.Itch.v2.0
 *   Nasdaq.NsmEquities.TotalView.Itch.v1.0
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
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>

void proto_register_nsmequities_totalview(void);
void proto_reg_handoff_nsmequities_totalview(void);

static dissector_handle_t nsmequities_totalview_handle;

static int proto_nsmequities_totalview;

/*
 * NsmEquities TotalView Protocol
 */

#define NSMEQUITIES_TOTALVIEW_PROTOCOL_NAME "Nasdaq TotalView Itch"
#define NSMEQUITIES_TOTALVIEW_PROTOCOL_SHORT "NSMEQUITIES.TOTALVIEW"
#define NSMEQUITIES_TOTALVIEW_PROTOCOL_FILTER "nsmequities.totalview"

/*
 * NsmEquities TotalView Header
 */

#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_HEADER_SIZE 3 /* Client Soup Bin Tcp Packet */
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_HEADER_SIZE 3 /* Server Soup Bin Tcp Packet */
#define NSMEQUITIES_TOTALVIEW_PACKET_HEADER_SIZE 20 /* Packet Header */

/*
 * NsmEquities TotalView Field Handles
 */

static int hf_nsmequities_totalview_accepted_sequence_number;
static int hf_nsmequities_totalview_accepted_sequence_number_v502023;
static int hf_nsmequities_totalview_accepted_session;
static int hf_nsmequities_totalview_attribution;
static int hf_nsmequities_totalview_auction_collar_extension;
static int hf_nsmequities_totalview_auction_collar_reference_price;
static int hf_nsmequities_totalview_authenticity;
static int hf_nsmequities_totalview_breached_level;
static int hf_nsmequities_totalview_buy_sell_indicator;
static int hf_nsmequities_totalview_canceled_shares;
static int hf_nsmequities_totalview_canceled_shares_v32;
static int hf_nsmequities_totalview_canceled_shares_v10;
static int hf_nsmequities_totalview_client_packet_type;
static int hf_nsmequities_totalview_contra_broker_code;
static int hf_nsmequities_totalview_count;
static int hf_nsmequities_totalview_cross_price;
static int hf_nsmequities_totalview_cross_price_v32;
static int hf_nsmequities_totalview_cross_shares;
static int hf_nsmequities_totalview_cross_type;
static int hf_nsmequities_totalview_current_reference_price;
static int hf_nsmequities_totalview_current_reference_price_v32;
static int hf_nsmequities_totalview_debug_text;
static int hf_nsmequities_totalview_display;
static int hf_nsmequities_totalview_etp_flag;
static int hf_nsmequities_totalview_etp_leverage_factor;
static int hf_nsmequities_totalview_event_code;
static int hf_nsmequities_totalview_executed_shares;
static int hf_nsmequities_totalview_executed_shares_v32;
static int hf_nsmequities_totalview_executed_shares_v10;
static int hf_nsmequities_totalview_execution_price;
static int hf_nsmequities_totalview_execution_price_v32;
static int hf_nsmequities_totalview_far_price;
static int hf_nsmequities_totalview_far_price_v32;
static int hf_nsmequities_totalview_financial_status_indicator;
static int hf_nsmequities_totalview_imbalance_direction;
static int hf_nsmequities_totalview_imbalance_shares;
static int hf_nsmequities_totalview_imbalance_shares_v32;
static int hf_nsmequities_totalview_interest_flag;
static int hf_nsmequities_totalview_inverse_indicator;
static int hf_nsmequities_totalview_ipo_flag;
static int hf_nsmequities_totalview_ipo_price;
static int hf_nsmequities_totalview_ipo_quotation_release_qualifier;
static int hf_nsmequities_totalview_ipo_quotation_release_time;
static int hf_nsmequities_totalview_issue_classification;
static int hf_nsmequities_totalview_issue_sub_type;
static int hf_nsmequities_totalview_length;
static int hf_nsmequities_totalview_level_1;
static int hf_nsmequities_totalview_level_2;
static int hf_nsmequities_totalview_level_3;
static int hf_nsmequities_totalview_locate_code;
static int hf_nsmequities_totalview_lower_auction_collar_price;
static int hf_nsmequities_totalview_lower_price_range_collar;
static int hf_nsmequities_totalview_luld_reference_price_tier;
static int hf_nsmequities_totalview_market_category;
static int hf_nsmequities_totalview_market_code;
static int hf_nsmequities_totalview_market_maker_mode;
static int hf_nsmequities_totalview_market_participant_state;
static int hf_nsmequities_totalview_match_number;
static int hf_nsmequities_totalview_match_number_v32;
static int hf_nsmequities_totalview_match_number_v30;
static int hf_nsmequities_totalview_maximum_allowable_price;
static int hf_nsmequities_totalview_message_count;
static int hf_nsmequities_totalview_message_length;
static int hf_nsmequities_totalview_message_type;
static int hf_nsmequities_totalview_millisecond;
static int hf_nsmequities_totalview_minimum_allowable_price;
static int hf_nsmequities_totalview_mmid;
static int hf_nsmequities_totalview_mpid;
static int hf_nsmequities_totalview_nanoseconds;
static int hf_nsmequities_totalview_near_execution_price;
static int hf_nsmequities_totalview_near_execution_time;
static int hf_nsmequities_totalview_near_price;
static int hf_nsmequities_totalview_near_price_v32;
static int hf_nsmequities_totalview_new_order_reference_number;
static int hf_nsmequities_totalview_new_order_reference_number_v32;
static int hf_nsmequities_totalview_open_eligibility_status;
static int hf_nsmequities_totalview_operational_halt_action;
static int hf_nsmequities_totalview_order_reference_number;
static int hf_nsmequities_totalview_order_reference_number_v32;
static int hf_nsmequities_totalview_order_reference_number_v30;
static int hf_nsmequities_totalview_original_order_reference_number;
static int hf_nsmequities_totalview_original_order_reference_number_v32;
static int hf_nsmequities_totalview_packet_length;
static int hf_nsmequities_totalview_paired_shares;
static int hf_nsmequities_totalview_paired_shares_v32;
static int hf_nsmequities_totalview_password;
static int hf_nsmequities_totalview_password_v32;
static int hf_nsmequities_totalview_price;
static int hf_nsmequities_totalview_price_v32;
static int hf_nsmequities_totalview_price_v10;
static int hf_nsmequities_totalview_price_variation_indicator;
static int hf_nsmequities_totalview_primary_market_maker;
static int hf_nsmequities_totalview_printable;
static int hf_nsmequities_totalview_reason;
static int hf_nsmequities_totalview_reason_code;
static int hf_nsmequities_totalview_reg_sho_action;
static int hf_nsmequities_totalview_reject_reason_code;
static int hf_nsmequities_totalview_requested_sequence_number;
static int hf_nsmequities_totalview_requested_sequence_number_v502023;
static int hf_nsmequities_totalview_requested_sequence_number_v32;
static int hf_nsmequities_totalview_requested_sequence_number_v30;
static int hf_nsmequities_totalview_requested_session;
static int hf_nsmequities_totalview_requested_session_v32;
static int hf_nsmequities_totalview_reserved;
static int hf_nsmequities_totalview_round_lot_size;
static int hf_nsmequities_totalview_round_lot_size_v32;
static int hf_nsmequities_totalview_round_lots_only;
static int hf_nsmequities_totalview_second;
static int hf_nsmequities_totalview_second_v32;
static int hf_nsmequities_totalview_sequence;
static int hf_nsmequities_totalview_sequence_number;
static int hf_nsmequities_totalview_sequence_number_v30;
static int hf_nsmequities_totalview_sequenced_message_type;
static int hf_nsmequities_totalview_server_packet_type;
static int hf_nsmequities_totalview_session;
static int hf_nsmequities_totalview_session_v30;
static int hf_nsmequities_totalview_session_v10;
static int hf_nsmequities_totalview_shares;
static int hf_nsmequities_totalview_shares_v20a;
static int hf_nsmequities_totalview_shares_v10;
static int hf_nsmequities_totalview_shares_numeric_6;
static int hf_nsmequities_totalview_shares_numeric_9;
static int hf_nsmequities_totalview_short_sale_threshold_indicator;
static int hf_nsmequities_totalview_side;
static int hf_nsmequities_totalview_stock;
static int hf_nsmequities_totalview_stock_v40;
static int hf_nsmequities_totalview_stock_alpha_6;
static int hf_nsmequities_totalview_stock_alpha_8;
static int hf_nsmequities_totalview_stock_alphabetic_6;
static int hf_nsmequities_totalview_stock_alphanumeric_6;
static int hf_nsmequities_totalview_stock_alphanumeric_8;
static int hf_nsmequities_totalview_stock_halted;
static int hf_nsmequities_totalview_stock_locate;
static int hf_nsmequities_totalview_text;
static int hf_nsmequities_totalview_timestamp;
static int hf_nsmequities_totalview_timestamp_v20a;
static int hf_nsmequities_totalview_timestamp_v10;
static int hf_nsmequities_totalview_tracking_number;
static int hf_nsmequities_totalview_trading_state;
static int hf_nsmequities_totalview_unsequenced_message;
static int hf_nsmequities_totalview_unsequenced_message_type;
static int hf_nsmequities_totalview_upper_auction_collar_price;
static int hf_nsmequities_totalview_upper_price_range_collar;
static int hf_nsmequities_totalview_username;
static int hf_nsmequities_totalview_username_v32;
static int hf_nsmequities_totalview_time_of_day;
static int hf_nsmequities_totalview_utc;
static int hf_nsmequities_totalview_local;
static int hf_nsmequities_totalview_elapsed_hundredths;
static int hf_nsmequities_totalview_elapsed_milliseconds;
static int hf_nsmequities_totalview_elapsed_nanoseconds;
static int hf_nsmequities_totalview_elapsed_seconds;

/* The time of day a timestamp reads as, beneath the instant it names */
#define NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_NAME "Time Of Day"
#define NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_FILTER "nsmequities.totalview.timeofday"
#define NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_DESCRIPTION "Time of day composed from the second the feed established and the count within it"

/* The instant a time of day names, dated by the frame that carried it */
#define NSMEQUITIES_TOTALVIEW_UTC_NAME "Utc"
#define NSMEQUITIES_TOTALVIEW_UTC_FILTER "nsmequities.totalview.utc"
#define NSMEQUITIES_TOTALVIEW_UTC_DESCRIPTION "The instant the time of day names, dated by the frame that carried the message"

/* The same instant as the reader's own clock reads it */
#define NSMEQUITIES_TOTALVIEW_LOCAL_NAME "Local"
#define NSMEQUITIES_TOTALVIEW_LOCAL_FILTER "nsmequities.totalview.local"
#define NSMEQUITIES_TOTALVIEW_LOCAL_DESCRIPTION "The instant the time of day names, in the reader's own timezone"

/* The count the wire carries, under the reading of it */
#define NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_NAME "Hundredths"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_FILTER "nsmequities.totalview.elapsed.hundredths"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_DESCRIPTION "The count since midnight the message states, as the wire carries it"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_NAME "Milliseconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_FILTER "nsmequities.totalview.elapsed.milliseconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_NAME "Nanoseconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_FILTER "nsmequities.totalview.elapsed.nanoseconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_NAME "Seconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_FILTER "nsmequities.totalview.elapsed.seconds"
#define NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"

/*
 * NsmEquities TotalView Subtrees
 */

static int ett_nsmequities_totalview;
static int ett_nsmequities_totalview_header;
static int ett_nsmequities_totalview_message;
static int ett_nsmequities_totalview_timestamp;
static int ett_nsmequities_totalview_client_packet_header;
static int ett_nsmequities_totalview_server_packet_header;
static int ett_nsmequities_totalview_message_header;
static int ett_nsmequities_totalview_sequenced_message_header;
static int ett_nsmequities_totalview_message_header_v30;
static int ett_nsmequities_totalview_sequenced_message_header_v20a;
static int ett_nsmequities_totalview_message_header_v20a;
static int ett_nsmequities_totalview_sequenced_message_header_v10;

/*
 * NsmEquities TotalView Expert Information
 */

/* Message length does not account for the parsed fields */
#define NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_FILTER "nsmequities.totalview.length.invalid"
#define NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_GROUP PI_MALFORMED
#define NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_SEVERITY PI_ERROR
#define NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_nsmequities_totalview_length;

/*
 * NsmEquities TotalView Preferences
 */

#define NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_NAME "version"
#define NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_TITLE "Protocol version"
#define NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define NSMEQUITIES_TOTALVIEW_VERSION_AUTOMATIC 0
#define NSMEQUITIES_TOTALVIEW_VERSION_5_0_2026     1
#define NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023     2
#define NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022     3
#define NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018     4
#define NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017     5
#define NSMEQUITIES_TOTALVIEW_VERSION_4_1     6
#define NSMEQUITIES_TOTALVIEW_VERSION_3_2     7
#define NSMEQUITIES_TOTALVIEW_VERSION_4_0     8
#define NSMEQUITIES_TOTALVIEW_VERSION_3_1     9
#define NSMEQUITIES_TOTALVIEW_VERSION_3_1_f     10
#define NSMEQUITIES_TOTALVIEW_VERSION_4_0_f     11
#define NSMEQUITIES_TOTALVIEW_VERSION_3_0     12
#define NSMEQUITIES_TOTALVIEW_VERSION_2_0_a     13
#define NSMEQUITIES_TOTALVIEW_VERSION_2_0     14
#define NSMEQUITIES_TOTALVIEW_VERSION_1_0     15

static const enum_val_t nsmequities_totalview_version_vals[] = {
    { "automatic", "Automatic (by send time)", NSMEQUITIES_TOTALVIEW_VERSION_AUTOMATIC },
    { "v5.0.2026", "5.0.2026", NSMEQUITIES_TOTALVIEW_VERSION_5_0_2026 },
    { "v5.0.2023", "5.0.2023", NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023 },
    { "v5.0.2022", "5.0.2022", NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022 },
    { "v5.0.2018", "5.0.2018", NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018 },
    { "v5.0.2017", "5.0.2017", NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017 },
    { "v4.1", "4.1", NSMEQUITIES_TOTALVIEW_VERSION_4_1 },
    { "v3.2", "3.2", NSMEQUITIES_TOTALVIEW_VERSION_3_2 },
    { "v4.0", "4.0", NSMEQUITIES_TOTALVIEW_VERSION_4_0 },
    { "v3.1", "3.1", NSMEQUITIES_TOTALVIEW_VERSION_3_1 },
    { "v3.1.f", "3.1.f", NSMEQUITIES_TOTALVIEW_VERSION_3_1_f },
    { "v4.0.f", "4.0.f", NSMEQUITIES_TOTALVIEW_VERSION_4_0_f },
    { "v3.0", "3.0", NSMEQUITIES_TOTALVIEW_VERSION_3_0 },
    { "v2.0.a", "2.0.a", NSMEQUITIES_TOTALVIEW_VERSION_2_0_a },
    { "v2.0", "2.0", NSMEQUITIES_TOTALVIEW_VERSION_2_0 },
    { "v1.0", "1.0", NSMEQUITIES_TOTALVIEW_VERSION_1_0 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
nsmequities_totalview_version_name(int version)
{
    switch (version) {
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2026:
        return "5.0.2026";
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023:
        return "5.0.2023";
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022:
        return "5.0.2022";
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018:
        return "5.0.2018";
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017:
        return "5.0.2017";
    case NSMEQUITIES_TOTALVIEW_VERSION_4_1:
        return "4.1";
    case NSMEQUITIES_TOTALVIEW_VERSION_3_2:
        return "3.2";
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0:
        return "4.0";
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1:
        return "3.1";
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1_f:
        return "3.1.f";
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0_f:
        return "4.0.f";
    case NSMEQUITIES_TOTALVIEW_VERSION_3_0:
        return "3.0";
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0_a:
        return "2.0.a";
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0:
        return "2.0";
    case NSMEQUITIES_TOTALVIEW_VERSION_1_0:
        return "1.0";
    }

    return "";
}

static int nsmequities_totalview_pref_version = NSMEQUITIES_TOTALVIEW_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2026 UINT64_C(1752451200) /* 2025-07-14 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2023 UINT64_C(1682640000) /* 2023-04-28 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2022 UINT64_C(1646611200) /* 2022-03-07 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2018 UINT64_C(1528070400) /* 2018-06-04 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2017 UINT64_C(1511136000) /* 2017-11-20 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_1 UINT64_C(1402531200) /* 2014-06-12 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_2 UINT64_C(1402531200) /* 2014-06-12 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_0 UINT64_C(1225497600) /* 2008-11-01 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_1 UINT64_C(1286323200) /* 2010-10-06 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_1_f UINT64_C(1247011200) /* 2009-07-08 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_0_f UINT64_C(1243555200) /* 2009-05-29 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_0 UINT64_C(1221523200) /* 2008-09-16 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_2_0_a UINT64_C(1171497600) /* 2007-02-15 */
#define NSMEQUITIES_TOTALVIEW_EFFECTIVE_2_0 UINT64_C(1041552000) /* 2003-01-03 */

/* Show preferences, one per message and struct */
#define NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_NAME "show.sessionmessages"
#define NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE "Show Session Messages"
#define NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION "Show Session Messages in the protocol tree"

#define NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_NAME "show.messages"
#define NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_TITLE "Show Messages"
#define NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_DESCRIPTION "Show Messages in the protocol tree"

static bool nsmequities_totalview_show_headers = true;
static bool nsmequities_totalview_show_session_messages = true;
static bool nsmequities_totalview_show_application_messages = true;
static bool nsmequities_totalview_show_messages = true;

/* Decimal places shown, the wire precision by default */
#define NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_NAME "decimal.places"
#define NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned nsmequities_totalview_pref_decimal_places = 8;

/* Millisecond read as a time of day, which is the default */
#define NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_NAME "read.millisecond"
#define NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_TITLE "Read Millisecond as a time"
#define NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_DESCRIPTION "Read Millisecond as a time of day, with the instant it names beneath it. Off states the milliseconds since midnight the wire carries and nothing else"

static bool nsmequities_totalview_pref_read_millisecond = true;

/* Nanoseconds read as a time of day, which is the default */
#define NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_NAME "read.nanoseconds"
#define NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_TITLE "Read Nanoseconds as a time"
#define NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_DESCRIPTION "Read Nanoseconds as a time of day, with the instant it names beneath it. Off states the nanoseconds since midnight the wire carries and nothing else"

static bool nsmequities_totalview_pref_read_nanoseconds = true;

/* Second read as a time of day, which is the default */
#define NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_NAME "read.second"
#define NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_TITLE "Read Second as a time"
#define NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_DESCRIPTION "Read Second as a time of day, with the instant it names beneath it. Off states the seconds since midnight the wire carries and nothing else"

static bool nsmequities_totalview_pref_read_second = true;

/* Timestamp read as a time of day, which is the default */
#define NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_NAME "read.timestamp"
#define NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_TITLE "Read Timestamp as a time"
#define NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_DESCRIPTION "Read Timestamp as a time of day, with the instant it names beneath it. Off states the nanoseconds since midnight the wire carries and nothing else"

static bool nsmequities_totalview_pref_read_timestamp = true;

/* Connection roles, Client is the initiator, Server is the acceptor */
#define NSMEQUITIES_TOTALVIEW_ROLE_RESOLVE 0
#define NSMEQUITIES_TOTALVIEW_ROLE_INITIATOR 1
#define NSMEQUITIES_TOTALVIEW_ROLE_ACCEPTOR 2

#define NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_NAME "role.assume"
#define NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_TITLE "Assume role"
#define NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_DESCRIPTION "Connection role assumed for every frame, for captures that start mid conversation"
#define NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_NAME "role.acceptorport"
#define NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_TITLE "Acceptor port"
#define NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION "Port the acceptor listens on, 0 resolves each frame's role from its conversation"
#define NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_NAME "role.swapsides"
#define NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_TITLE "Swap sides"
#define NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_DESCRIPTION "The first frame seen of each conversation was the acceptor's, not the initiator's, for captures that start mid conversation"

static int nsmequities_totalview_pref_assume_role = NSMEQUITIES_TOTALVIEW_ROLE_RESOLVE;
static unsigned nsmequities_totalview_pref_acceptor_port = 0;
static bool nsmequities_totalview_pref_swap_sides = false;

static const enum_val_t nsmequities_totalview_assume_role_vals[] = {
    { "resolve", "Resolve from the conversation", NSMEQUITIES_TOTALVIEW_ROLE_RESOLVE },
    { "initiator", "Initiator (Client)", NSMEQUITIES_TOTALVIEW_ROLE_INITIATOR },
    { "acceptor", "Acceptor (Server)", NSMEQUITIES_TOTALVIEW_ROLE_ACCEPTOR },
    { NULL, NULL, 0 }
};

/* Entries of a repeating group are numbered */
#define NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_NAME "show.indexes"
#define NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_TITLE "Show Indexes"
#define NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_DESCRIPTION "Number the entries of a repeating group in the protocol tree"

static bool nsmequities_totalview_pref_show_indexes = true;

/*
 * NsmEquities TotalView Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
nsmequities_totalview_version(uint64_t seconds)
{
    if (nsmequities_totalview_pref_version != NSMEQUITIES_TOTALVIEW_VERSION_AUTOMATIC) {
        return nsmequities_totalview_pref_version;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2026) {
        return NSMEQUITIES_TOTALVIEW_VERSION_5_0_2026;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2023) {
        return NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2022) {
        return NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2018) {
        return NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_5_0_2017) {
        return NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_1) {
        return NSMEQUITIES_TOTALVIEW_VERSION_4_1;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_2) {
        return NSMEQUITIES_TOTALVIEW_VERSION_3_2;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_0) {
        return NSMEQUITIES_TOTALVIEW_VERSION_4_0;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_1) {
        return NSMEQUITIES_TOTALVIEW_VERSION_3_1;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_1_f) {
        return NSMEQUITIES_TOTALVIEW_VERSION_3_1_f;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_4_0_f) {
        return NSMEQUITIES_TOTALVIEW_VERSION_4_0_f;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_3_0) {
        return NSMEQUITIES_TOTALVIEW_VERSION_3_0;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_2_0_a) {
        return NSMEQUITIES_TOTALVIEW_VERSION_2_0_a;
    }

    if (seconds >= NSMEQUITIES_TOTALVIEW_EFFECTIVE_2_0) {
        return NSMEQUITIES_TOTALVIEW_VERSION_2_0;
    }

    return NSMEQUITIES_TOTALVIEW_VERSION_1_0;
}

/* Label an offset from midnight as the clock reads it */
static void
nsmequities_totalview_time_of_day_label(char *buf, size_t size, const nstime_t *time)
{
    uint32_t seconds = (uint32_t)time->secs;

    snprintf(buf, size, "%02u:%02u:%02u.%09u",
        seconds / 3600, (seconds / 60) % 60, seconds % 60, (uint32_t)time->nsecs);
}

/* What this protocol remembers across the frames of a conversation */
typedef struct nsmequities_totalview_conversation {
    address initiator;
    uint32_t port;
    bool swapped;
    uint64_t seconds;
} nsmequities_totalview_conversation;

/* Record of the frame's conversation, created on its first frame */
static nsmequities_totalview_conversation *
nsmequities_totalview_conversation_of(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    nsmequities_totalview_conversation *state = (nsmequities_totalview_conversation *)conversation_get_proto_data(conversation, proto_nsmequities_totalview);

    if (state == NULL) {
        state = wmem_new0(wmem_file_scope(), nsmequities_totalview_conversation);
        copy_address_wmem(wmem_file_scope(), &state->initiator, &pinfo->src);
        state->port = pinfo->srcport;
        conversation_add_proto_data(conversation, proto_nsmequities_totalview, state);
    }

    return state;
}

/* The second the dissection in progress sits in */
static uint64_t nsmequities_totalview_anchor;

/* Seed the second from the frame's own record, the frames before it
   established it and a later pass must read the same value */
static void
nsmequities_totalview_anchor_begin(packet_info *pinfo)
{
    uint64_t *seconds = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_totalview, 0);

    if (seconds == NULL) {
        seconds = wmem_new0(wmem_file_scope(), uint64_t);
        *seconds = nsmequities_totalview_conversation_of(pinfo)->seconds;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_totalview, 0, seconds);
    }

    nsmequities_totalview_anchor = *seconds;
}

/* The feed established a second, the messages after it count from it */
static void
nsmequities_totalview_anchor_set(packet_info *pinfo, uint64_t seconds)
{
    nsmequities_totalview_anchor = seconds;

    if (!pinfo->fd->visited) {
        nsmequities_totalview_conversation_of(pinfo)->seconds = seconds;
    }
}

/* Date a count from midnight by the frame that carried it. The day is
   settled once per frame, from the first time of day read out of it: the
   messages a frame carries share the day it arrived, and a later pass over
   the frame must read what the first one settled on */
static void
nsmequities_totalview_utc(packet_info *pinfo, uint64_t seconds, uint32_t nanoseconds, nstime_t *instant)
{
    int64_t *midnight = (int64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_totalview, 1);

    if (midnight == NULL) {
        int64_t settled = (int64_t)pinfo->abs_ts.secs - (int64_t)seconds;

        midnight = wmem_new0(wmem_file_scope(), int64_t);
        *midnight = (settled + (settled < 0 ? -450 : 450)) / 900 * 900;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_totalview, 1, midnight);
    }

    instant->secs = (time_t)(*midnight + (int64_t)seconds);
    instant->nsecs = (int)nanoseconds;
}

/* Cap the fraction at the preferred decimal places */
static void
nsmequities_totalview_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = nsmequities_totalview_pref_decimal_places;

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
nsmequities_totalview_format_decimal_4_32(char *buf, uint32_t raw)
{
    int64_t value = (int32_t)raw;
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

    nsmequities_totalview_decimal_places(buf);
}

/* Format an implied 8 decimal place value */
static void
nsmequities_totalview_format_decimal_8_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t whole = value / 100000000;
    int64_t fraction = value % 100000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && whole == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%08" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%08" PRId64, whole, fraction);
    }

    nsmequities_totalview_decimal_places(buf);
}

/* Broadcast endpoints from the connectivity model */
typedef struct nsmequities_totalview_endpoint {
    uint8_t address[4];
    uint16_t port;
    const char *name;
} nsmequities_totalview_endpoint;

static const nsmequities_totalview_endpoint nsmequities_totalview_endpoints[] = {
    { { 233, 187, 20, 0 }, 18070, "Feed A Chicago Metro Area" },
    { { 233, 187, 20, 64 }, 18070, "Feed B Chicago Metro Area" },
    { { 233, 54, 12, 111 }, 26477, "Feed A New York Metro Area" },
    { { 233, 49, 196, 111 }, 26477, "Feed B New York Metro Area" },
    { { 233, 86, 230, 143 }, 26477, "New Jersey Metro Area" },
    { { 233, 86, 230, 144 }, 26400, "New Jersey Metro Area" },
    { { 233, 54, 12, 101 }, 26400, "New York Metro Area" },
};

/* The published endpoint a frame was sent to, NULL for any other destination */
static const nsmequities_totalview_endpoint *
nsmequities_totalview_endpoint_of(packet_info *pinfo)
{
    if (pinfo->net_dst.type != AT_IPv4 || pinfo->net_dst.len != 4) {
        return NULL;
    }

    for (size_t index = 0; index < array_length(nsmequities_totalview_endpoints); index++) {
        const nsmequities_totalview_endpoint *endpoint = &nsmequities_totalview_endpoints[index];

        if (pinfo->destport == endpoint->port && memcmp(pinfo->net_dst.data, endpoint->address, 4) == 0) {
            return endpoint;
        }
    }

    return NULL;
}

/*
 * NsmEquities TotalView Fields
 */

/* Accepted Sequence Number */
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_NAME        "Accepted Sequence Number"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION "The sequence number in ASCII of the next Sequenced Message to be sent. Left padded with spaces."
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_FILTER      "nsmequities.totalview.acceptedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_nsmequities_totalview_accepted_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_accepted_sequence_number, tvb, offset, NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_SIZE;
}

/* Accepted Sequence Number V502023 */
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_NAME        "Accepted Sequence Number"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_DESCRIPTION "The sequence number in ASCII of the next Sequenced Message to be sent. Left padded with spaces."
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_FILTER      "nsmequities.totalview.acceptedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_SIZE        20

static unsigned
parse_nsmequities_totalview_accepted_sequence_number_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_accepted_sequence_number_v502023, tvb, offset, NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_SIZE;
}

/* Accepted Session */
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_NAME        "Accepted Session"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_DESCRIPTION "The session ID of the session that is now logged into. Left padded with spaces."
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_FILTER      "nsmequities.totalview.acceptedsession"
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_SIZE        10

static unsigned
parse_nsmequities_totalview_accepted_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_accepted_session, tvb, offset, NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_SIZE, NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_SIZE;
}

/* Attribution */
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_NAME        "Attribution"
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_DESCRIPTION "Nasdaq market participant identifier associated with the entered order"
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_FILTER      "nsmequities.totalview.attribution"
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ATTRIBUTION_SIZE        4

static unsigned
parse_nsmequities_totalview_attribution(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_attribution, tvb, offset, NSMEQUITIES_TOTALVIEW_ATTRIBUTION_SIZE, NSMEQUITIES_TOTALVIEW_ATTRIBUTION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ATTRIBUTION_SIZE;
}

/* Auction Collar Extension */
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_NAME        "Auction Collar Extension"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_DESCRIPTION "Indicates the number of extensions to the Reopening Auction"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_FILTER      "nsmequities.totalview.auctioncollarextension"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_SIZE        4

static unsigned
parse_nsmequities_totalview_auction_collar_extension(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_auction_collar_extension, tvb, offset, NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_SIZE, NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_SIZE;
}

/* Auction Collar Reference Price */
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_NAME        "Auction Collar Reference Price"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_DESCRIPTION "Reference price used to set the auction collars"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_FILTER      "nsmequities.totalview.auctioncollarreferenceprice"
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_auction_collar_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_auction_collar_reference_price, tvb, offset, NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_SIZE;
}

/* Authenticity */
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_NAME        "Authenticity"
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_DESCRIPTION "Denotes if an issue or quoting participant record is set-up in NASDAQ systems in a live/production, test, or demo state"
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_FILTER      "nsmequities.totalview.authenticity"
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_AUTHENTICITY_SIZE        1

static const value_string nsmequities_totalview_authenticity_vals[] = {
    { 'P', "Live Production" },
    { 'T', "Test" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_authenticity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_authenticity, tvb, offset, NSMEQUITIES_TOTALVIEW_AUTHENTICITY_SIZE, NSMEQUITIES_TOTALVIEW_AUTHENTICITY_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_AUTHENTICITY_SIZE;
}

/* Breached Level */
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_NAME        "Breached Level"
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_DESCRIPTION "Denotes the MWCB Level that was breached"
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_FILTER      "nsmequities.totalview.breachedlevel"
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_SIZE        1

static const value_string nsmequities_totalview_breached_level_vals[] = {
    { '1', "Level 1" },
    { '2', "Level 2" },
    { '3', "Level 3" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_breached_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_breached_level, tvb, offset, NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_SIZE, NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_SIZE;
}

/* Buy Sell Indicator */
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_NAME        "Buy Sell Indicator"
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_DESCRIPTION "The type of order being added"
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_FILTER      "nsmequities.totalview.buysellindicator"
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_SIZE        1

static const value_string nsmequities_totalview_buy_sell_indicator_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_buy_sell_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_buy_sell_indicator, tvb, offset, NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_SIZE, NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_SIZE;
}

/* Canceled Shares */
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_NAME        "Canceled Shares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_DESCRIPTION "The number of shares being removed from the display size of the order as the result of a cancellation"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_FILTER      "nsmequities.totalview.canceledshares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_SIZE        4

static unsigned
parse_nsmequities_totalview_canceled_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_canceled_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_SIZE;
}

/* Canceled Shares V32 */
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_NAME        "Canceled Shares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_DESCRIPTION "The number of shares being removed from the display size of the order as the result of a cancellation."
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_FILTER      "nsmequities.totalview.canceledshares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_SIZE        6

static unsigned
parse_nsmequities_totalview_canceled_shares_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_canceled_shares_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_SIZE;
}

/* Canceled Shares V10 */
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_NAME        "Canceled Shares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_DESCRIPTION "The number of shares canceled."
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_FILTER      "nsmequities.totalview.canceledshares"
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_SIZE        9

static unsigned
parse_nsmequities_totalview_canceled_shares_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_canceled_shares_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_SIZE;
}

/* Client Packet Type values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET            '+'
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET    'L'
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET 'U'
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET 'R'
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET   'O'

/* Client Packet Type */
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_NAME        "Client Packet Type"
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the client"
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_FILTER      "nsmequities.totalview.clientpackettype"
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_SIZE        1

static const value_string nsmequities_totalview_client_packet_type_vals[] = {
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request Packet" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_client_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_client_packet_type, tvb, offset, NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_SIZE;
}

/* Contra Broker Code */
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_NAME        "Contra Broker Code"
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_DESCRIPTION "The four-letter symbol of the firm that executed this order if the executing order was not entered directly on NASDAQ. Blank filled if an NASDAQ subscriber entered the executing order directly on NASDAQ."
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_FILTER      "nsmequities.totalview.contrabrokercode"
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_SIZE        4

static unsigned
parse_nsmequities_totalview_contra_broker_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_contra_broker_code, tvb, offset, NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_SIZE, NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_SIZE;
}

/* Count values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_COUNT_HEARTBEAT      0
#define NSMEQUITIES_TOTALVIEW_COUNT_END_OF_SESSION 65535

/* Count */
#define NSMEQUITIES_TOTALVIEW_COUNT_NAME        "Count"
#define NSMEQUITIES_TOTALVIEW_COUNT_DESCRIPTION "Number of messages to follow this header"
#define NSMEQUITIES_TOTALVIEW_COUNT_FILTER      "nsmequities.totalview.count"
#define NSMEQUITIES_TOTALVIEW_COUNT_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_COUNT_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_COUNT_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define NSMEQUITIES_TOTALVIEW_COUNT_SIZE        2

static unsigned
parse_nsmequities_totalview_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_count, tvb, offset, NSMEQUITIES_TOTALVIEW_COUNT_SIZE, NSMEQUITIES_TOTALVIEW_COUNT_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_COUNT_SIZE;
}

/* Cross Price */
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_NAME        "Cross Price"
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_DESCRIPTION "The price at which the cross occurred"
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_FILTER      "nsmequities.totalview.crossprice"
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_cross_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_cross_price, tvb, offset, NSMEQUITIES_TOTALVIEW_CROSS_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_CROSS_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CROSS_PRICE_SIZE;
}

/* Cross Price V32 */
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_NAME        "Cross Price"
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_DESCRIPTION "The price at which the cross occurred. Refer to Data Types for field processing notes."
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_FILTER      "nsmequities.totalview.crossprice"
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_cross_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_cross_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_SIZE;
}

/* Cross Shares */
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_NAME        "Cross Shares"
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_DESCRIPTION "The number of shares matched in the Nasdaq Cross"
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_FILTER      "nsmequities.totalview.crossshares"
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_CROSS_SHARES_SIZE        8

static unsigned
parse_nsmequities_totalview_cross_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_cross_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_CROSS_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_CROSS_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CROSS_SHARES_SIZE;
}

/* Cross Type */
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_NAME        "Cross Type"
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_DESCRIPTION "The Nasdaq cross session for which the message is being generated"
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_FILTER      "nsmequities.totalview.crosstype"
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CROSS_TYPE_SIZE        1

static const value_string nsmequities_totalview_cross_type_vals[] = {
    { 'O', "Opening" },
    { 'C', "Closing" },
    { 'H', "Halted Or Paused" },
    { 'A', "Extended Close" },
    { 'I', "Intraday Cross And Post Close Cross" },
    { 'E', "Emc Cross" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_cross_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_cross_type, tvb, offset, NSMEQUITIES_TOTALVIEW_CROSS_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_CROSS_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CROSS_TYPE_SIZE;
}

/* Current Reference Price */
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_NAME        "Current Reference Price"
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_DESCRIPTION "The price at which the NOII shares are being calculated"
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_FILTER      "nsmequities.totalview.currentreferenceprice"
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_current_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_current_reference_price, tvb, offset, NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_SIZE;
}

/* Current Reference Price V32 */
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_NAME        "Current Reference Price"
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_DESCRIPTION "The price at which the NOII shares are being calculated."
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_FILTER      "nsmequities.totalview.currentreferenceprice"
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_current_reference_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_current_reference_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_SIZE;
}

/* Debug Text */
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_NAME        "Debug Text"
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_DESCRIPTION "Free form human readable text"
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_FILTER      "nsmequities.totalview.debugtext"
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_SIZE        1

static unsigned
parse_nsmequities_totalview_debug_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_debug_text, tvb, offset, NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_SIZE, NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_SIZE;
}

/* Display */
#define NSMEQUITIES_TOTALVIEW_DISPLAY_NAME        "Display"
#define NSMEQUITIES_TOTALVIEW_DISPLAY_DESCRIPTION "Indicates the Display code for the order."
#define NSMEQUITIES_TOTALVIEW_DISPLAY_FILTER      "nsmequities.totalview.display"
#define NSMEQUITIES_TOTALVIEW_DISPLAY_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_DISPLAY_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_DISPLAY_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_DISPLAY_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_DISPLAY_SIZE        1

static const value_string nsmequities_totalview_display_vals[] = {
    { 'Y', "Displayable" },
    { 'S', "Flash Order" },
    { 'A', "Attributable" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_display(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_display, tvb, offset, NSMEQUITIES_TOTALVIEW_DISPLAY_SIZE, NSMEQUITIES_TOTALVIEW_DISPLAY_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_DISPLAY_SIZE;
}

/* Etp Flag */
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_NAME        "Etp Flag"
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_DESCRIPTION "Indicates whether the security is an exchange traded product"
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_FILTER      "nsmequities.totalview.etpflag"
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ETP_FLAG_SIZE        1

static const value_string nsmequities_totalview_etp_flag_vals[] = {
    { 'Y', "Etp" },
    { 'N', "Not Etp" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_etp_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_etp_flag, tvb, offset, NSMEQUITIES_TOTALVIEW_ETP_FLAG_SIZE, NSMEQUITIES_TOTALVIEW_ETP_FLAG_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ETP_FLAG_SIZE;
}

/* Etp Leverage Factor */
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_NAME        "Etp Leverage Factor"
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_DESCRIPTION "Tracks the integral relationship of the ETP to the underlying index"
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_FILTER      "nsmequities.totalview.etpleveragefactor"
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_SIZE        4

static unsigned
parse_nsmequities_totalview_etp_leverage_factor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_etp_leverage_factor, tvb, offset, NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_SIZE, NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_SIZE;
}

/* Event Code */
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_NAME        "Event Code"
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_DESCRIPTION "System Event Codes"
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_FILTER      "nsmequities.totalview.eventcode"
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_EVENT_CODE_SIZE        1

static const value_string nsmequities_totalview_event_code_vals[] = {
    { 'O', "Start Of Messages" },
    { 'S', "Start Of System Hours" },
    { 'Q', "Start Of Market Hours" },
    { 'M', "End Of Market Hours" },
    { 'E', "End Of System Hours" },
    { 'C', "End Of Messages" },
    { 'A', "Emergency Market Condition Halt" },
    { 'R', "Emergency Market Condition Quote Only Period" },
    { 'B', "Emergency Market Condition Resumption" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_event_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_event_code, tvb, offset, NSMEQUITIES_TOTALVIEW_EVENT_CODE_SIZE, NSMEQUITIES_TOTALVIEW_EVENT_CODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_EVENT_CODE_SIZE;
}

/* Executed Shares */
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_NAME        "Executed Shares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_DESCRIPTION "The number of shares executed"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_FILTER      "nsmequities.totalview.executedshares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_SIZE        4

static unsigned
parse_nsmequities_totalview_executed_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_executed_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_SIZE;
}

/* Executed Shares V32 */
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_NAME        "Executed Shares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_DESCRIPTION "The number of shares executed."
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_FILTER      "nsmequities.totalview.executedshares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_SIZE        6

static unsigned
parse_nsmequities_totalview_executed_shares_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_executed_shares_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_SIZE;
}

/* Executed Shares V10 */
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_NAME        "Executed Shares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_DESCRIPTION "The number of shares executed."
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_FILTER      "nsmequities.totalview.executedshares"
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_SIZE        9

static unsigned
parse_nsmequities_totalview_executed_shares_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_executed_shares_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_SIZE;
}

/* Execution Price */
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_NAME        "Execution Price"
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_DESCRIPTION "The price at which the order execution occurred"
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_FILTER      "nsmequities.totalview.executionprice"
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_execution_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_execution_price, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_SIZE;
}

/* Execution Price V32 */
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_NAME        "Execution Price"
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_DESCRIPTION "The price at which the order execution occurred. Refer to Data Types for field processing notes."
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_FILTER      "nsmequities.totalview.executionprice"
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_execution_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_execution_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_SIZE;
}

/* Far Price */
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_NAME        "Far Price"
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_DESCRIPTION "A hypothetical auction-clearing price for cross orders only"
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_FILTER      "nsmequities.totalview.farprice"
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_far_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_far_price, tvb, offset, NSMEQUITIES_TOTALVIEW_FAR_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_FAR_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_FAR_PRICE_SIZE;
}

/* Far Price V32 */
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_NAME        "Far Price"
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_DESCRIPTION "A hypothetical auction-clearing price for cross orders only."
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_FILTER      "nsmequities.totalview.farprice"
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_far_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_far_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_SIZE;
}

/* Financial Status Indicator */
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_NAME        "Financial Status Indicator"
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_DESCRIPTION "Indicates when a firm is not in compliance with NASDAQ continued listing requirements"
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_FILTER      "nsmequities.totalview.financialstatusindicator"
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_SIZE        1

static const value_string nsmequities_totalview_financial_status_indicator_vals[] = {
    { 'D', "Deficient" },
    { 'E', "Delinquent" },
    { 'Q', "Bankrupt" },
    { 'S', "Suspended" },
    { 'G', "Deficient And Bankrupt" },
    { 'H', "Deficient And Delinquent" },
    { 'J', "Delinquent And Bankrupt" },
    { 'K', "Deficient Delinquent And Bankrupt" },
    { 'C', "Creations And Redemptions Suspended" },
    { 'N', "Normal" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_financial_status_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_financial_status_indicator, tvb, offset, NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_SIZE, NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_SIZE;
}

/* Imbalance Direction */
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_NAME        "Imbalance Direction"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_DESCRIPTION "The market side of the order imbalance"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_FILTER      "nsmequities.totalview.imbalancedirection"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_SIZE        1

static const value_string nsmequities_totalview_imbalance_direction_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'N', "None" },
    { 'O', "Insufficient Orders" },
    { 'P', "Paused" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_imbalance_direction(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_imbalance_direction, tvb, offset, NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_SIZE, NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_SIZE;
}

/* Imbalance Shares */
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_NAME        "Imbalance Shares"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_DESCRIPTION "The number of shares not paired at the Current Reference Price"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_FILTER      "nsmequities.totalview.imbalanceshares"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_SIZE        8

static unsigned
parse_nsmequities_totalview_imbalance_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_imbalance_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_SIZE;
}

/* Imbalance Shares V32 */
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_NAME        "Imbalance Shares"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_DESCRIPTION "The number of shares not paired at the Current Reference Price."
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_FILTER      "nsmequities.totalview.imbalanceshares"
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_SIZE        9

static unsigned
parse_nsmequities_totalview_imbalance_shares_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_imbalance_shares_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_SIZE;
}

/* Interest Flag */
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_NAME        "Interest Flag"
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_DESCRIPTION "Interest Flag"
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_FILTER      "nsmequities.totalview.interestflag"
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_SIZE        1

static const value_string nsmequities_totalview_interest_flag_vals[] = {
    { 'B', "Buy Side" },
    { 'S', "Sell Side" },
    { 'A', "Both Sides" },
    { 'N', "No Rpi Orders Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_interest_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_interest_flag, tvb, offset, NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_SIZE, NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_SIZE;
}

/* Inverse Indicator */
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_NAME        "Inverse Indicator"
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_DESCRIPTION "Indicates the directional relationship between the ETP and underlying index. Example: An ETP Leverage Factor of 3 and an Inverse value of 'Y' indicates the ETP will decrease by a value of 3."
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_FILTER      "nsmequities.totalview.inverseindicator"
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_SIZE        1

static const value_string nsmequities_totalview_inverse_indicator_vals[] = {
    { 'Y', "Inverse Etp" },
    { 'N', "Not Inverse Etp" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_inverse_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_inverse_indicator, tvb, offset, NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_SIZE, NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_SIZE;
}

/* Ipo Flag */
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_NAME        "Ipo Flag"
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_DESCRIPTION "Indicates if the NASDAQ security is set up for IPO release"
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_FILTER      "nsmequities.totalview.ipoflag"
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_IPO_FLAG_SIZE        1

static const value_string nsmequities_totalview_ipo_flag_vals[] = {
    { 'Y', "Set Up For Ipo Release" },
    { 'N', "Not Set Up For Ipo Release" },
    { 'Z', "Non Ipo New Listed Security" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_ipo_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_ipo_flag, tvb, offset, NSMEQUITIES_TOTALVIEW_IPO_FLAG_SIZE, NSMEQUITIES_TOTALVIEW_IPO_FLAG_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IPO_FLAG_SIZE;
}

/* Ipo Price */
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_NAME        "Ipo Price"
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_DESCRIPTION "Denotes the IPO price to be used for intraday net change calculations"
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_FILTER      "nsmequities.totalview.ipoprice"
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_IPO_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_ipo_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_ipo_price, tvb, offset, NSMEQUITIES_TOTALVIEW_IPO_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_IPO_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IPO_PRICE_SIZE;
}

/* Ipo Quotation Release Qualifier */
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_NAME        "Ipo Quotation Release Qualifier"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_DESCRIPTION "IPO Quotation Release Qualifier"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_FILTER      "nsmequities.totalview.ipoquotationreleasequalifier"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_SIZE        1

static const value_string nsmequities_totalview_ipo_quotation_release_qualifier_vals[] = {
    { 'A', "Anticipated Quotation Release Time" },
    { 'C', "Ipo Release Canceled Or Postponed" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_ipo_quotation_release_qualifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_ipo_quotation_release_qualifier, tvb, offset, NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_SIZE, NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_SIZE;
}

/* Ipo Quotation Release Time */
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_NAME        "Ipo Quotation Release Time"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_DESCRIPTION "Denotes the IPO release time, in seconds since midnight, for quotation to the nearest second"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_FILTER      "nsmequities.totalview.ipoquotationreleasetime"
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_SIZE        4

static unsigned
parse_nsmequities_totalview_ipo_quotation_release_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_ipo_quotation_release_time, tvb, offset, NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_SIZE, NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_SIZE;
}

/* Issue Classification */
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_NAME        "Issue Classification"
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_DESCRIPTION "Identifies the security class for the issue as assigned by NASDAQ"
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_FILTER      "nsmequities.totalview.issueclassification"
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_SIZE        1

static const value_string nsmequities_totalview_issue_classification_vals[] = {
    { 'A', "American Depositary Share" },
    { 'B', "Bond" },
    { 'C', "Common Stock" },
    { 'F', "Depository Receipt" },
    { 'I', "Sec 144 A" },
    { 'L', "Limited Partnership" },
    { 'N', "Notes" },
    { 'O', "Ordinary Share" },
    { 'P', "Preferred Stock" },
    { 'Q', "Other Securities" },
    { 'R', "Right" },
    { 'S', "Shares Of Beneficial Interest" },
    { 'T', "Convertible Debenture" },
    { 'U', "Unit" },
    { 'V', "Units Of Beneficial Interest" },
    { 'W', "Warrant" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_issue_classification(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_issue_classification, tvb, offset, NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_SIZE, NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_SIZE;
}

/* Issue Sub Type */
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_NAME        "Issue Sub Type"
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_DESCRIPTION "Identifies the security sub-type for the issue as assigned by NASDAQ"
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_FILTER      "nsmequities.totalview.issuesubtype"
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_SIZE        2

static const string_string nsmequities_totalview_issue_sub_type_vals[] = {
    { "A", "Preferred Trust Securities" },
    { "AI", "Alpha Index Et Ns" },
    { "B", "Index Based Derivative" },
    { "C", "Common Shares" },
    { "CB", "Commodity Based Trust Shares" },
    { "CF", "Commodity Futures Trust Shares" },
    { "CL", "Commodity Linked Securities" },
    { "CM", "Commodity Index Trust Shares" },
    { "CO", "Collateralized Mortgage Obligation" },
    { "CT", "Currency Trust Shares" },
    { "CU", "Commodity Currency Linked Securities" },
    { "CW", "Currency Warrants" },
    { "D", "Global Depositary Shares" },
    { "E", "Etf Portfolio Depositary Receipt" },
    { "EG", "Equity Gold Shares" },
    { "EI", "Etn Equity Index Linked Securities" },
    { "EM", "Next Shares Exchange Traded Managed Fund" },
    { "EN", "Exchange Traded Notes" },
    { "EU", "Equity Units" },
    { "F", "Holdrs" },
    { "FI", "Etn Fixed Income Linked Securities" },
    { "FL", "Etn Futures Linked Securities" },
    { "G", "Global Shares" },
    { "I", "Etf Index Fund Shares" },
    { "IR", "Interest Rate" },
    { "IW", "Index Warrant" },
    { "IX", "Index Linked Exchangeable Notes" },
    { "J", "Corporate Backed Trust Security" },
    { "L", "Contingent Litigation Right" },
    { "LL", "Limited Liability Company" },
    { "M", "Equity Based Derivative" },
    { "MF", "Managed Fund Shares" },
    { "ML", "Etn Multi Factor Index Linked Securities" },
    { "MT", "Managed Trust Securities" },
    { "N", "Ny Registry Shares" },
    { "O", "Open Ended Mutual Fund" },
    { "P", "Privately Held Security" },
    { "PP", "Poison Pill" },
    { "PU", "Partnership Units" },
    { "Q", "Closed End Funds" },
    { "R", "Reg S" },
    { "RC", "Commodity Redeemable Commodity Linked Securities" },
    { "RF", "Etn Redeemable Futures Linked Securities" },
    { "RT", "Reit" },
    { "RU", "Commodity Redeemable Currency Linked Securities" },
    { "S", "Seed" },
    { "SC", "Spot Rate Closing" },
    { "SI", "Spot Rate Intraday" },
    { "T", "Tracking Stock" },
    { "TC", "Trust Certificates" },
    { "TU", "Trust Units" },
    { "U", "Portal" },
    { "V", "Contingent Value Right" },
    { "W", "Trust Issued Receipts" },
    { "WC", "World Currency Option" },
    { "X", "Trust" },
    { "Y", "Other" },
    { "Z", "Not Applicable" },
    { NULL, NULL }
};

static unsigned
parse_nsmequities_totalview_issue_sub_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    char *value = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_ENCODING);

    /* Left justified and filled with spaces */
    value = g_strchomp(value);

    proto_tree_add_string_format_value(tree, hf_nsmequities_totalview_issue_sub_type, tvb, offset, NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_SIZE, value,
        "%s", str_to_str_wmem(pinfo->pool, value, nsmequities_totalview_issue_sub_type_vals, "Unknown (%s)"));

    return offset + NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_SIZE;
}

/* Length */
#define NSMEQUITIES_TOTALVIEW_LENGTH_NAME        "Length"
#define NSMEQUITIES_TOTALVIEW_LENGTH_DESCRIPTION "Length of data message not including this field"
#define NSMEQUITIES_TOTALVIEW_LENGTH_FILTER      "nsmequities.totalview.length"
#define NSMEQUITIES_TOTALVIEW_LENGTH_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_LENGTH_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LENGTH_SIZE        2

static unsigned
parse_nsmequities_totalview_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_length, tvb, offset, NSMEQUITIES_TOTALVIEW_LENGTH_SIZE, NSMEQUITIES_TOTALVIEW_LENGTH_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LENGTH_SIZE;
}

/* Level 1 */
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_NAME        "Level 1"
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_DESCRIPTION "Denotes the MWCB Level 1 Value."
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_FILTER      "nsmequities.totalview.level1"
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_TYPE        FT_INT64
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LEVEL_1_SIZE        8

static unsigned
parse_nsmequities_totalview_level_1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_level_1, tvb, offset, NSMEQUITIES_TOTALVIEW_LEVEL_1_SIZE, NSMEQUITIES_TOTALVIEW_LEVEL_1_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LEVEL_1_SIZE;
}

/* Level 2 */
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_NAME        "Level 2"
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_DESCRIPTION "Denotes the MWCB Level 2 Value."
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_FILTER      "nsmequities.totalview.level2"
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_TYPE        FT_INT64
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LEVEL_2_SIZE        8

static unsigned
parse_nsmequities_totalview_level_2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_level_2, tvb, offset, NSMEQUITIES_TOTALVIEW_LEVEL_2_SIZE, NSMEQUITIES_TOTALVIEW_LEVEL_2_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LEVEL_2_SIZE;
}

/* Level 3 */
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_NAME        "Level 3"
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_DESCRIPTION "Denotes the MWCB Level 3 Value."
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_FILTER      "nsmequities.totalview.level3"
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_TYPE        FT_INT64
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LEVEL_3_SIZE        8

static unsigned
parse_nsmequities_totalview_level_3(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_level_3, tvb, offset, NSMEQUITIES_TOTALVIEW_LEVEL_3_SIZE, NSMEQUITIES_TOTALVIEW_LEVEL_3_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LEVEL_3_SIZE;
}

/* Locate Code */
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_NAME        "Locate Code"
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_DESCRIPTION "Locate code identifying the security"
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_FILTER      "nsmequities.totalview.locatecode"
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LOCATE_CODE_SIZE        2

static unsigned
parse_nsmequities_totalview_locate_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_locate_code, tvb, offset, NSMEQUITIES_TOTALVIEW_LOCATE_CODE_SIZE, NSMEQUITIES_TOTALVIEW_LOCATE_CODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LOCATE_CODE_SIZE;
}

/* Lower Auction Collar Price */
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_NAME        "Lower Auction Collar Price"
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_DESCRIPTION "Indicates the price of the lower auction collar threshold"
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_FILTER      "nsmequities.totalview.lowerauctioncollarprice"
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_lower_auction_collar_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_lower_auction_collar_price, tvb, offset, NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_SIZE;
}

/* Lower Price Range Collar */
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_NAME        "Lower Price Range Collar"
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_DESCRIPTION "Indicates the price of the Lower Auction Collar Threshold"
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_FILTER      "nsmequities.totalview.lowerpricerangecollar"
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_SIZE        4

static unsigned
parse_nsmequities_totalview_lower_price_range_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_lower_price_range_collar, tvb, offset, NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_SIZE, NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_SIZE;
}

/* Luld Reference Price Tier */
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_NAME        "Luld Reference Price Tier"
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_DESCRIPTION "Indicates which Limit Up / Limit Down price band calculation parameter is to be used for the instrument"
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_FILTER      "nsmequities.totalview.luldreferencepricetier"
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_SIZE        1

static const value_string nsmequities_totalview_luld_reference_price_tier_vals[] = {
    { '1', "Tier 1" },
    { '2', "Tier 2" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_luld_reference_price_tier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_luld_reference_price_tier, tvb, offset, NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_SIZE, NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_SIZE;
}

/* Market Category */
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_NAME        "Market Category"
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_DESCRIPTION "Indicates listing market or listing market tier for the issue"
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_FILTER      "nsmequities.totalview.marketcategory"
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_SIZE        1

static const value_string nsmequities_totalview_market_category_vals[] = {
    { 'Q', "Nasdaq Global Select Market" },
    { 'G', "Nasdaq Global Market" },
    { 'S', "Nasdaq Capital Market" },
    { 'N', "Nyse" },
    { 'A', "Nyse American" },
    { 'P', "Nyse Arca" },
    { 'M', "Nyse Texas" },
    { 'Z', "Bats Z" },
    { 'V', "Investors Exchange" },
    { ' ', "Not Available" },
    { 'T', "Cqs" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_market_category(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_market_category, tvb, offset, NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_SIZE, NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_SIZE;
}

/* Market Code */
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_NAME        "Market Code"
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_DESCRIPTION "Market Code"
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_FILTER      "nsmequities.totalview.marketcode"
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MARKET_CODE_SIZE        1

static const value_string nsmequities_totalview_market_code_vals[] = {
    { 'Q', "Nasdaq" },
    { 'B', "Nasdaq Texas" },
    { 'X', "Psx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_market_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_market_code, tvb, offset, NSMEQUITIES_TOTALVIEW_MARKET_CODE_SIZE, NSMEQUITIES_TOTALVIEW_MARKET_CODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MARKET_CODE_SIZE;
}

/* Market Maker Mode */
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_NAME        "Market Maker Mode"
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_DESCRIPTION "Indicates the quoting participant's registration status in relation to SEC Rules 101 and 104 of Regulation M"
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_FILTER      "nsmequities.totalview.marketmakermode"
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_SIZE        1

static const value_string nsmequities_totalview_market_maker_mode_vals[] = {
    { 'N', "Normal" },
    { 'P', "Passive" },
    { 'S', "Syndicate" },
    { 'R', "Pre Syndicate" },
    { 'L', "Penalty" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_market_maker_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_market_maker_mode, tvb, offset, NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_SIZE, NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_SIZE;
}

/* Market Participant State */
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_NAME        "Market Participant State"
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_DESCRIPTION "Indicates the market participant's current registration status in the issue"
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_FILTER      "nsmequities.totalview.marketparticipantstate"
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_SIZE        1

static const value_string nsmequities_totalview_market_participant_state_vals[] = {
    { 'A', "Active" },
    { 'E', "Excused" },
    { 'W', "Withdrawn" },
    { 'S', "Suspended" },
    { 'D', "Deleted" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_market_participant_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_market_participant_state, tvb, offset, NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_SIZE, NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_SIZE;
}

/* Match Number */
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_NAME        "Match Number"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_DESCRIPTION "The Nasdaq generated day-unique Match Number of this execution"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_FILTER      "nsmequities.totalview.matchnumber"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_SIZE        8

static unsigned
parse_nsmequities_totalview_match_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_match_number, tvb, offset, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_SIZE;
}

/* Match Number V32 */
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_NAME        "Match Number"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_DESCRIPTION "The NASDAQ generated day-unique Match Number of this execution. The match number is also referenced in the Trade Break Message."
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_FILTER      "nsmequities.totalview.matchnumber"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_SIZE        12

static unsigned
parse_nsmequities_totalview_match_number_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_match_number_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_SIZE;
}

/* Match Number V30 */
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_NAME        "Match Number"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_DESCRIPTION "The NASDAQ generated day-unique Match Number of this execution. The match number is also referenced in the Trade Break Message."
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_FILTER      "nsmequities.totalview.matchnumber"
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_SIZE        9

static unsigned
parse_nsmequities_totalview_match_number_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_match_number_v30, tvb, offset, NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_SIZE;
}

/* Maximum Allowable Price */
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_NAME        "Maximum Allowable Price"
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_DESCRIPTION "80% above Registration Statement Highest Price"
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_FILTER      "nsmequities.totalview.maximumallowableprice"
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_maximum_allowable_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_maximum_allowable_price, tvb, offset, NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_SIZE;
}

/* Message Count values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_HEARTBEAT      0
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_END_OF_SESSION 65535

/* Message Count */
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_NAME        "Message Count"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_DESCRIPTION "Number of messages to follow this header"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_FILTER      "nsmequities.totalview.messagecount"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_SIZE        2

static unsigned
parse_nsmequities_totalview_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_message_count, tvb, offset, NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_SIZE, NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_SIZE;
}

/* Message Length */
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_NAME        "Message Length"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_DESCRIPTION "Length of data message not including this field"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_FILTER      "nsmequities.totalview.messagelength"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_nsmequities_totalview_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_message_length, tvb, offset, NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_SIZE, NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_SIZE;
}

/* Message Type values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT                                       'S'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY                                    'R'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION                               'H'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR 'Y'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION                        'L'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL                                 'V'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL                                  'W'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE                          'K'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR                                'J'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT                                   'h'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION                      'A'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION                    'F'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED                                     'E'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE                          'C'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL                                       'X'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE                                       'D'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE                                      'U'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE                                    'P'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE                                        'Q'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE                                       'B'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR                      'I'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR                 'N'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY  'O'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP                                          'T'
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS                                       'M'

/* Message Type */
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NAME        "Message Type"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DESCRIPTION "Code identifying this message type"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_FILTER      "nsmequities.totalview.messagetype"
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SIZE        1

static const value_string nsmequities_totalview_message_type_vals[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY, "Direct Listing With Capital Raise Price Discovery Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_message_type, tvb, offset, NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SIZE;
}

/* Millisecond */
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_NAME        "Millisecond"
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_DESCRIPTION "Number of milliseconds since last second."
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_FILTER      "nsmequities.totalview.millisecond"
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_TYPE        FT_RELATIVE_TIME
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE        3

static unsigned
parse_nsmequities_totalview_millisecond(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, ENC_ASCII);

    uint64_t counted = (uint64_t)strtoull(text, NULL, 10);

    nstime_t elapsed = {
        .secs = (time_t)(counted / 1000),
        .nsecs = (int)(counted % 1000) * 1000000,
    };

    proto_tree_add_time(tree, hf_nsmequities_totalview_millisecond, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, &elapsed);

    if (nsmequities_totalview_pref_read_millisecond) {
        /* The second the feed established composes the time of day */
        nstime_t time = {
            .secs = (time_t)(nsmequities_totalview_anchor + counted / 1000),
            .nsecs = (int)(counted % 1000) * 1000000,
        };

        nstime_t instant;

        nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

        proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_utc, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, &instant);

        proto_item_set_generated(reading);

        /* The span since midnight the two together count out */
        uint64_t total = nsmequities_totalview_anchor * 1000 + counted;

        proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

        char clock[32];

        nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

        proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, &time, "%s", clock));
        proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, &instant));
        proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_milliseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE, total);

    }

    return offset + NSMEQUITIES_TOTALVIEW_MILLISECOND_SIZE;
}

/* Minimum Allowable Price */
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_NAME        "Minimum Allowable Price"
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_DESCRIPTION "20% below Registration Statement Lower Price"
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_FILTER      "nsmequities.totalview.minimumallowableprice"
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_minimum_allowable_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_minimum_allowable_price, tvb, offset, NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_SIZE;
}

/* Mmid */
#define NSMEQUITIES_TOTALVIEW_MMID_NAME        "Mmid"
#define NSMEQUITIES_TOTALVIEW_MMID_DESCRIPTION "The MMID of the firm entering the Attributable order. Optional: present only if the Display field is set to \"A\"."
#define NSMEQUITIES_TOTALVIEW_MMID_FILTER      "nsmequities.totalview.mmid"
#define NSMEQUITIES_TOTALVIEW_MMID_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_MMID_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_MMID_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MMID_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MMID_SIZE        4

static unsigned
parse_nsmequities_totalview_mmid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_mmid, tvb, offset, NSMEQUITIES_TOTALVIEW_MMID_SIZE, NSMEQUITIES_TOTALVIEW_MMID_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MMID_SIZE;
}

/* Mpid */
#define NSMEQUITIES_TOTALVIEW_MPID_NAME        "Mpid"
#define NSMEQUITIES_TOTALVIEW_MPID_DESCRIPTION "Denotes the market participant identifier for which the position message is being generated"
#define NSMEQUITIES_TOTALVIEW_MPID_FILTER      "nsmequities.totalview.mpid"
#define NSMEQUITIES_TOTALVIEW_MPID_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_MPID_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_MPID_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_MPID_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_MPID_SIZE        4

static unsigned
parse_nsmequities_totalview_mpid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_mpid, tvb, offset, NSMEQUITIES_TOTALVIEW_MPID_SIZE, NSMEQUITIES_TOTALVIEW_MPID_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_MPID_SIZE;
}

/* Nanoseconds */
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_NAME        "Nanoseconds"
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_DESCRIPTION "Nanoseconds portion of the timestamp."
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_FILTER      "nsmequities.totalview.nanoseconds"
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_TYPE        FT_RELATIVE_TIME
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_ENCODING    ENC_TIME_NSECS | ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE        4

static unsigned
parse_nsmequities_totalview_nanoseconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t counted = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(tree, hf_nsmequities_totalview_nanoseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE, NSMEQUITIES_TOTALVIEW_NANOSECONDS_ENCODING);

    if (nsmequities_totalview_pref_read_nanoseconds) {
        /* The second the feed established composes the time of day */
        nstime_t time = {
            .secs = (time_t)(nsmequities_totalview_anchor + counted / 1000000000),
            .nsecs = (int)(counted % 1000000000) * 1,
        };

        nstime_t instant;

        nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

        proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_utc, tvb, offset, NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE, &instant);

        proto_item_set_generated(reading);

        /* The span since midnight the two together count out */
        uint64_t total = nsmequities_totalview_anchor * 1000000000 + counted;

        proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

        char clock[32];

        nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

        proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE, &time, "%s", clock));
        proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE, &instant));
        proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_nanoseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE, total);

    }

    return offset + NSMEQUITIES_TOTALVIEW_NANOSECONDS_SIZE;
}

/* Near Execution Price */
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_NAME        "Near Execution Price"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_DESCRIPTION "The current reference price when the DLCR volatility test has successfully passed"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_FILTER      "nsmequities.totalview.nearexecutionprice"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_near_execution_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_near_execution_price, tvb, offset, NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_SIZE;
}

/* Near Execution Time */
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_NAME        "Near Execution Time"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_DESCRIPTION "The time at which the Near Execution Price was determined"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_FILTER      "nsmequities.totalview.nearexecutiontime"
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_SIZE        8

static unsigned
parse_nsmequities_totalview_near_execution_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_near_execution_time, tvb, offset, NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_SIZE, NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_SIZE;
}

/* Near Price */
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_NAME        "Near Price"
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_DESCRIPTION "A hypothetical auction-clearing price for cross orders as well as continuous orders"
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_FILTER      "nsmequities.totalview.nearprice"
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_near_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_near_price, tvb, offset, NSMEQUITIES_TOTALVIEW_NEAR_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_NEAR_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_NEAR_PRICE_SIZE;
}

/* Near Price V32 */
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_NAME        "Near Price"
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_DESCRIPTION "A hypothetical auction-clearing price for cross orders as well as continuous orders."
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_FILTER      "nsmequities.totalview.nearprice"
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_near_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_near_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_SIZE;
}

/* New Order Reference Number */
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_NAME        "New Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_DESCRIPTION "The new reference number for this order at time of replacement"
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_FILTER      "nsmequities.totalview.neworderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_SIZE        8

static unsigned
parse_nsmequities_totalview_new_order_reference_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_new_order_reference_number, tvb, offset, NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_SIZE;
}

/* New Order Reference Number V32 */
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_NAME        "New Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION "The new reference number for this order. Note that new reference numbers mean new time priority, so this order belongs below other orders at the same price in priority."
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_FILTER      "nsmequities.totalview.neworderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_SIZE        12

static unsigned
parse_nsmequities_totalview_new_order_reference_number_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_new_order_reference_number_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_SIZE;
}

/* Open Eligibility Status */
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_NAME        "Open Eligibility Status"
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_DESCRIPTION "Indicates if the security is eligible to be released for trading"
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_FILTER      "nsmequities.totalview.openeligibilitystatus"
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_SIZE        1

static const value_string nsmequities_totalview_open_eligibility_status_vals[] = {
    { 'N', "Not Eligible" },
    { 'Y', "Eligible" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_open_eligibility_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_open_eligibility_status, tvb, offset, NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_SIZE, NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_SIZE;
}

/* Operational Halt Action */
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_NAME        "Operational Halt Action"
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_DESCRIPTION "Indicates the operational halt action for the security"
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_FILTER      "nsmequities.totalview.operationalhaltaction"
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_SIZE        1

static const value_string nsmequities_totalview_operational_halt_action_vals[] = {
    { 'H', "Halted" },
    { 'T', "Trading Resumed" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_operational_halt_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_operational_halt_action, tvb, offset, NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_SIZE, NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_SIZE;
}

/* Order Reference Number */
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_NAME        "Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_DESCRIPTION "The unique reference number assigned to the new order at the time of receipt"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_FILTER      "nsmequities.totalview.orderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_SIZE        8

static unsigned
parse_nsmequities_totalview_order_reference_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_order_reference_number, tvb, offset, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_SIZE;
}

/* Order Reference Number V32 */
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_NAME        "Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION "The unique reference number assigned to the new order."
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_FILTER      "nsmequities.totalview.orderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_SIZE        12

static unsigned
parse_nsmequities_totalview_order_reference_number_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_order_reference_number_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_SIZE;
}

/* Order Reference Number V30 */
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_NAME        "Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_DESCRIPTION "The unique reference number assigned to the new order. The order reference number is increasing, but not necessarily sequential."
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_FILTER      "nsmequities.totalview.orderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_SIZE        9

static unsigned
parse_nsmequities_totalview_order_reference_number_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_order_reference_number_v30, tvb, offset, NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_SIZE;
}

/* Original Order Reference Number */
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_NAME        "Original Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_DESCRIPTION "The original reference number of the order being replaced"
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_FILTER      "nsmequities.totalview.originalorderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_SIZE        8

static unsigned
parse_nsmequities_totalview_original_order_reference_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_original_order_reference_number, tvb, offset, NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_SIZE;
}

/* Original Order Reference Number V32 */
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_NAME        "Original Order Reference Number"
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION "The original reference number of the order being replaced."
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_FILTER      "nsmequities.totalview.originalorderreferencenumber"
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_SIZE        12

static unsigned
parse_nsmequities_totalview_original_order_reference_number_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_original_order_reference_number_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_SIZE;
}

/* Packet Length */
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_NAME        "Packet Length"
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_DESCRIPTION "Length of data message not including this field"
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_FILTER      "nsmequities.totalview.packetlength"
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_SIZE        2

static unsigned
parse_nsmequities_totalview_packet_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_packet_length, tvb, offset, NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_SIZE, NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_SIZE;
}

/* Paired Shares */
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_NAME        "Paired Shares"
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_DESCRIPTION "The total number of shares that are eligible to be matched at the Current Reference Price"
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_FILTER      "nsmequities.totalview.pairedshares"
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_SIZE        8

static unsigned
parse_nsmequities_totalview_paired_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_paired_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_SIZE;
}

/* Paired Shares V32 */
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_NAME        "Paired Shares"
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_DESCRIPTION "The total number of shares that are eligible to be matched at the Current Reference Price."
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_FILTER      "nsmequities.totalview.pairedshares"
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_SIZE        9

static unsigned
parse_nsmequities_totalview_paired_shares_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_paired_shares_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_SIZE;
}

/* Password */
#define NSMEQUITIES_TOTALVIEW_PASSWORD_NAME        "Password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_DESCRIPTION "Login password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_FILTER      "nsmequities.totalview.password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_PASSWORD_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_PASSWORD_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PASSWORD_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PASSWORD_SIZE        10

static unsigned
parse_nsmequities_totalview_password(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_password, tvb, offset, NSMEQUITIES_TOTALVIEW_PASSWORD_SIZE, NSMEQUITIES_TOTALVIEW_PASSWORD_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PASSWORD_SIZE;
}

/* Password V32 */
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_NAME        "Password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_DESCRIPTION "Login password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_FILTER      "nsmequities.totalview.password"
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PASSWORD_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_password_v32(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_password_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_PASSWORD_V32_SIZE, NSMEQUITIES_TOTALVIEW_PASSWORD_V32_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PASSWORD_V32_SIZE;
}

/* Price */
#define NSMEQUITIES_TOTALVIEW_PRICE_NAME        "Price"
#define NSMEQUITIES_TOTALVIEW_PRICE_DESCRIPTION "The display price of the new order"
#define NSMEQUITIES_TOTALVIEW_PRICE_FILTER      "nsmequities.totalview.price"
#define NSMEQUITIES_TOTALVIEW_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_price, tvb, offset, NSMEQUITIES_TOTALVIEW_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PRICE_SIZE;
}

/* Price V32 */
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_NAME        "Price"
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_DESCRIPTION "The display price of the new order. Refer to Data Types for field processing notes."
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_FILTER      "nsmequities.totalview.price"
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_TYPE        FT_DOUBLE
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PRICE_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_PRICE_V32_SIZE, ENC_ASCII);

    double value = (double)strtoll(text, NULL, 10) / 1e4;

    proto_tree_add_double_format_value(tree, hf_nsmequities_totalview_price_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_PRICE_V32_SIZE, value, "%.4f", value);

    return offset + NSMEQUITIES_TOTALVIEW_PRICE_V32_SIZE;
}

/* Price V10 */
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_NAME        "Price"
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_DESCRIPTION "The limit price of the order. 9 whole number places, a decimal point, and 10 decimal digits."
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_FILTER      "nsmequities.totalview.price"
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PRICE_V10_SIZE        20

static unsigned
parse_nsmequities_totalview_price_v10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_price_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_PRICE_V10_SIZE, NSMEQUITIES_TOTALVIEW_PRICE_V10_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PRICE_V10_SIZE;
}

/* Price Variation Indicator */
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_NAME        "Price Variation Indicator"
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_DESCRIPTION "Indicates the absolute value of the percentage of deviation of the Near Indicative Clearing Price to the nearest Current Reference Price"
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_FILTER      "nsmequities.totalview.pricevariationindicator"
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_SIZE        1

static const value_string nsmequities_totalview_price_variation_indicator_vals[] = {
    { 'L', "Less Than 1 Percent" },
    { '1', "Less Than 2 Percent" },
    { '2', "Less Than 3 Percent" },
    { '3', "Less Than 4 Percent" },
    { '4', "Less Than 5 Percent" },
    { '5', "Less Than 6 Percent" },
    { '6', "Less Than 7 Percent" },
    { '7', "Less Than 8 Percent" },
    { '8', "Less Than 9 Percent" },
    { '9', "Less Than 10 Percent" },
    { 'A', "Less Than 20 Percent" },
    { 'B', "Less Than 30 Percent" },
    { 'C', "More Than 30 Percent" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_price_variation_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_price_variation_indicator, tvb, offset, NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_SIZE, NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_SIZE;
}

/* Primary Market Maker */
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_NAME        "Primary Market Maker"
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_DESCRIPTION "Indicates if the market participant firm qualifies as a Primary Market Maker in accordance with NASDAQ marketplace rules"
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_FILTER      "nsmequities.totalview.primarymarketmaker"
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_SIZE        1

static const value_string nsmequities_totalview_primary_market_maker_vals[] = {
    { 'Y', "Primary" },
    { 'N', "Non Primary" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_primary_market_maker(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_primary_market_maker, tvb, offset, NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_SIZE, NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_SIZE;
}

/* Printable */
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_NAME        "Printable"
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_DESCRIPTION "Indicates if the execution should be reflected on time and sale displays and volume calculations"
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_FILTER      "nsmequities.totalview.printable"
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_PRINTABLE_SIZE        1

static const value_string nsmequities_totalview_printable_vals[] = {
    { 'N', "No" },
    { 'Y', "Yes" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_printable(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_printable, tvb, offset, NSMEQUITIES_TOTALVIEW_PRINTABLE_SIZE, NSMEQUITIES_TOTALVIEW_PRINTABLE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_PRINTABLE_SIZE;
}

/* Reason */
#define NSMEQUITIES_TOTALVIEW_REASON_NAME        "Reason"
#define NSMEQUITIES_TOTALVIEW_REASON_DESCRIPTION "Trading Action reason."
#define NSMEQUITIES_TOTALVIEW_REASON_FILTER      "nsmequities.totalview.reason"
#define NSMEQUITIES_TOTALVIEW_REASON_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REASON_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REASON_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REASON_SIZE        4

static const string_string nsmequities_totalview_reason_vals[] = {
    { "T1", "Halt News Pending" },
    { "T2", "Halt News Disseminated" },
    { "T5", "Single Security Trading Pause In Effect" },
    { "T6", "Regulatory Halt Extraordinary Market Activity" },
    { "T8", "Halt Etf" },
    { "T12", "Trading Halted For Information Requested" },
    { "H4", "Halt Non Compliance" },
    { "H9", "Halt Filings Not Current" },
    { "H10", "Halt Sec Trading Suspension" },
    { "H11", "Halt Regulatory Concern" },
    { "O1", "Operations Halt" },
    { "LUDP", "Volatility Trading Pause" },
    { "LUDS", "Volatility Trading Pause Straddle Condition" },
    { "MWC1", "Market Wide Circuit Breaker Halt Level One" },
    { "MWC2", "Market Wide Circuit Breaker Halt Level Two" },
    { "MWC3", "Market Wide Circuit Breaker Halt Level Three" },
    { "MWC0", "Market Wide Circuit Breaker Halt Carry Over" },
    { "IPO1", "Ipo Issue Not Yet Trading" },
    { "M1", "Corporate Action" },
    { "M2", "Quotation Not Available" },
    { "T3", "News And Resumption Times" },
    { "T7", "Single Security Trading Pause Quotation Only Period" },
    { "R4", "Qualifications Issues Reviewed" },
    { "R9", "Filing Requirements Satisfied" },
    { "C3", "Issuer News Not Forthcoming" },
    { "C4", "Qualifications Halt Ended" },
    { "C9", "Qualifications Halt Concluded" },
    { "C11", "Trade Halt Concluded" },
    { "MWCQ", "Market Wide Circuit Breaker Resumption" },
    { "R1", "New Issue Available" },
    { "R2", "Issue Available" },
    { "IPOQ", "Ipo Security Released For Quotation" },
    { "IPOE", "Ipo Security Positioning Window Extension" },
    { "", "Reason Not Available" },
    { NULL, NULL }
};

static unsigned
parse_nsmequities_totalview_reason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    char *value = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_REASON_SIZE, NSMEQUITIES_TOTALVIEW_REASON_ENCODING);

    /* Left justified and filled with spaces */
    value = g_strchomp(value);

    proto_tree_add_string_format_value(tree, hf_nsmequities_totalview_reason, tvb, offset, NSMEQUITIES_TOTALVIEW_REASON_SIZE, value,
        "%s", str_to_str_wmem(pinfo->pool, value, nsmequities_totalview_reason_vals, "Unknown (%s)"));

    return offset + NSMEQUITIES_TOTALVIEW_REASON_SIZE;
}

/* Reason Code */
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_NAME        "Reason Code"
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_DESCRIPTION "Trading Action reason"
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_FILTER      "nsmequities.totalview.reasoncode"
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REASON_CODE_SIZE        4

static const string_string nsmequities_totalview_reason_code_vals[] = {
    { "T1", "Halt News Pending" },
    { "T2", "Halt News Disseminated" },
    { "T5", "Single Security Trading Pause In Effect" },
    { "T6", "Regulatory Halt Extraordinary Market Activity" },
    { "T8", "Halt Etf" },
    { "T12", "Trading Halted" },
    { "H4", "Halt Non Compliance" },
    { "H9", "Halt Filings Not Current" },
    { "H10", "Halt Sec Trading Suspension" },
    { "H11", "Halt Regulatory Concern" },
    { "O1", "Operations Halt" },
    { "LUDP", "Volatility Trading Pause" },
    { "LUDS", "Straddle Condition Trading Pause" },
    { "MWC1", "Circuit Breaker Halt Level 1" },
    { "MWC2", "Circuit Breaker Halt Level 2" },
    { "MWC3", "Circuit Breaker Halt Level 3" },
    { "MWC0", "Carry Over Circuit Breaker Halt" },
    { "IPO1", "Ipo Issue" },
    { "M1", "Corporate Action" },
    { "M2", "Not Available" },
    { "T3", "News And Resumption Times" },
    { "T7", "Trading Pause Quotation Only Period" },
    { "R4", "Qualifications Issues Resolved" },
    { "R9", "Filing Requirements Satisfied" },
    { "C3", "Issuer News Not Forthcoming" },
    { "C4", "Qualifications Halt Ended" },
    { "C9", "Qualifications Halt Concluded" },
    { "C11", "Trade Halt Concluded By Other Regulatory Authority" },
    { "MWCQ", "Market Wide Circuit Breaker Resumption" },
    { "R1", "New Issue Available" },
    { "R2", "Issue Available" },
    { "IPOQ", "Ipo Security Released" },
    { "IPOE", "Ipo Security Positioning Window Extension" },
    { "", "Reason Not Available" },
    { "", "Reason Not Available" },
    { NULL, NULL }
};

static unsigned
parse_nsmequities_totalview_reason_code(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    char *value = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_REASON_CODE_SIZE, NSMEQUITIES_TOTALVIEW_REASON_CODE_ENCODING);

    /* Left justified and filled with spaces */
    value = g_strchomp(value);

    proto_tree_add_string_format_value(tree, hf_nsmequities_totalview_reason_code, tvb, offset, NSMEQUITIES_TOTALVIEW_REASON_CODE_SIZE, value,
        "%s", str_to_str_wmem(pinfo->pool, value, nsmequities_totalview_reason_code_vals, "Unknown (%s)"));

    return offset + NSMEQUITIES_TOTALVIEW_REASON_CODE_SIZE;
}

/* Reg Sho Action */
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_NAME        "Reg Sho Action"
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_DESCRIPTION "Denotes the Reg SHO Short Sale Price Test Restriction status for the issue at the time of the message dissemination"
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_FILTER      "nsmequities.totalview.regshoaction"
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_SIZE        1

static const value_string nsmequities_totalview_reg_sho_action_vals[] = {
    { '0', "No Price Test" },
    { '1', "Reg Sho Short Sale Price Test Restriction" },
    { '2', "Test Restriction Remains" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_reg_sho_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_reg_sho_action, tvb, offset, NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_SIZE, NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_SIZE;
}

/* Reject Reason Code */
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_NAME        "Reject Reason Code"
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_DESCRIPTION "Login Reject Codes"
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_FILTER      "nsmequities.totalview.rejectreasoncode"
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_SIZE        1

static const value_string nsmequities_totalview_reject_reason_code_vals[] = {
    { 'A', "Not Authorized" },
    { 'S', "Session Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_reject_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_reject_reason_code, tvb, offset, NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_SIZE, NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_SIZE;
}

/* Requested Sequence Number */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_NAME        "Requested Sequence Number"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_FILTER      "nsmequities.totalview.requestedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_nsmequities_totalview_requested_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_requested_sequence_number, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_SIZE;
}

/* Requested Sequence Number V502023 */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_NAME        "Requested Sequence Number"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_FILTER      "nsmequities.totalview.requestedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_SIZE        20

static unsigned
parse_nsmequities_totalview_requested_sequence_number_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_requested_sequence_number_v502023, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_SIZE;
}

/* Requested Sequence Number V32 */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_NAME        "Requested Sequence Number"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_FILTER      "nsmequities.totalview.requestedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_SIZE        20

static unsigned
parse_nsmequities_totalview_requested_sequence_number_v32(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_requested_sequence_number_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_SIZE, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_SIZE;
}

/* Requested Sequence Number V30 */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_NAME        "Requested Sequence Number"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_FILTER      "nsmequities.totalview.requestedsequencenumber"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_SIZE        10

static unsigned
parse_nsmequities_totalview_requested_sequence_number_v30(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_requested_sequence_number_v30, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_SIZE, NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_SIZE;
}

/* Requested Session */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_NAME        "Requested Session"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_DESCRIPTION "Specifies the session the client would like to log into, or all blanks to log into the currently active session."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_FILTER      "nsmequities.totalview.requestedsession"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_SIZE        10

static unsigned
parse_nsmequities_totalview_requested_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_requested_session, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_SIZE, NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_SIZE;
}

/* Requested Session V32 */
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_NAME        "Requested Session"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_DESCRIPTION "Specifies the session the client would like to log into, or all blanks to log into the currently active session."
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_FILTER      "nsmequities.totalview.requestedsession"
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_SIZE        10

static unsigned
parse_nsmequities_totalview_requested_session_v32(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_requested_session_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_SIZE, NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_SIZE;
}

/* Reserved */
#define NSMEQUITIES_TOTALVIEW_RESERVED_NAME        "Reserved"
#define NSMEQUITIES_TOTALVIEW_RESERVED_DESCRIPTION "Reserved"
#define NSMEQUITIES_TOTALVIEW_RESERVED_FILTER      "nsmequities.totalview.reserved"
#define NSMEQUITIES_TOTALVIEW_RESERVED_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_RESERVED_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_RESERVED_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_RESERVED_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_RESERVED_SIZE        1

static unsigned
parse_nsmequities_totalview_reserved(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_reserved, tvb, offset, NSMEQUITIES_TOTALVIEW_RESERVED_SIZE, NSMEQUITIES_TOTALVIEW_RESERVED_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_RESERVED_SIZE;
}

/* Round Lot Size */
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_NAME        "Round Lot Size"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_DESCRIPTION "Denotes the number of shares that represent a round lot for the issue"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_FILTER      "nsmequities.totalview.roundlotsize"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_SIZE        4

static unsigned
parse_nsmequities_totalview_round_lot_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_round_lot_size, tvb, offset, NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_SIZE, NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_SIZE;
}

/* Round Lot Size V32 */
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_NAME        "Round Lot Size"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_DESCRIPTION "Indicates the number of shares that represent a round lot for the issue."
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_FILTER      "nsmequities.totalview.roundlotsize"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_SIZE        6

static unsigned
parse_nsmequities_totalview_round_lot_size_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_round_lot_size_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_SIZE;
}

/* Round Lots Only */
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_NAME        "Round Lots Only"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_DESCRIPTION "Indicates if Nasdaq system limits order entry for issue"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_FILTER      "nsmequities.totalview.roundlotsonly"
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_SIZE        1

static const value_string nsmequities_totalview_round_lots_only_vals[] = {
    { 'Y', "Yes" },
    { 'N', "No" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_round_lots_only(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_round_lots_only, tvb, offset, NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_SIZE, NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_SIZE;
}

/* Second */
#define NSMEQUITIES_TOTALVIEW_SECOND_NAME        "Second"
#define NSMEQUITIES_TOTALVIEW_SECOND_DESCRIPTION "Number of seconds since midnight."
#define NSMEQUITIES_TOTALVIEW_SECOND_FILTER      "nsmequities.totalview.second"
#define NSMEQUITIES_TOTALVIEW_SECOND_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_TOTALVIEW_SECOND_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_TOTALVIEW_SECOND_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SECOND_ENCODING    ENC_TIME_SECS | ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_SECOND_SIZE        4

static unsigned
parse_nsmequities_totalview_second(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t seconds = tvb_get_ntohl(tvb, offset);

    /* The messages after it count from this second */
    nsmequities_totalview_anchor_set(pinfo, seconds);

    if (!nsmequities_totalview_pref_read_second) {
        proto_tree_add_uint64(tree, hf_nsmequities_totalview_elapsed_seconds, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_SIZE, seconds);

        return offset + NSMEQUITIES_TOTALVIEW_SECOND_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(seconds / 1),
        .nsecs = (int)(seconds % 1) * 1000000000,
    };

    nstime_t instant;

    nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_second, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

    char clock[32];

    nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_seconds, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_SIZE, seconds);

    return offset + NSMEQUITIES_TOTALVIEW_SECOND_SIZE;
}

/* Second V32 */
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_NAME        "Second"
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_DESCRIPTION "Number of seconds since midnight."
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_FILTER      "nsmequities.totalview.second"
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_ENCODING    ENC_TIME_SECS | ENC_LITTLE_ENDIAN
#define NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE        5

static unsigned
parse_nsmequities_totalview_second_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, ENC_ASCII);

    uint64_t seconds = (uint64_t)strtoull(text, NULL, 10);

    /* The messages after it count from this second */
    nsmequities_totalview_anchor_set(pinfo, seconds);

    if (!nsmequities_totalview_pref_read_second) {
        proto_tree_add_uint64(tree, hf_nsmequities_totalview_elapsed_seconds, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, seconds);

        return offset + NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(seconds / 1),
        .nsecs = (int)(seconds % 1) * 1000000000,
    };

    nstime_t instant;

    nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_second_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

    char clock[32];

    nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_seconds, tvb, offset, NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE, seconds);

    return offset + NSMEQUITIES_TOTALVIEW_SECOND_V32_SIZE;
}

/* Sequence */
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NAME        "Sequence"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_DESCRIPTION "Sequence Number of the first message to follow this header"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_FILTER      "nsmequities.totalview.sequence"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_SIZE        4

static unsigned
parse_nsmequities_totalview_sequence(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_sequence, tvb, offset, NSMEQUITIES_TOTALVIEW_SEQUENCE_SIZE, NSMEQUITIES_TOTALVIEW_SEQUENCE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SEQUENCE_SIZE;
}

/* Sequence Number */
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_NAME        "Sequence Number"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_DESCRIPTION "Sequence number of the first message to follow this header"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_FILTER      "nsmequities.totalview.sequencenumber"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_nsmequities_totalview_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_sequence_number, tvb, offset, NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_SIZE;
}

/* Sequence Number V30 */
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_NAME        "Sequence Number"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_DESCRIPTION "The sequence number in ASCII of the next Sequenced Message to be sent. Left padded with spaces."
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_FILTER      "nsmequities.totalview.sequencenumber"
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_SIZE        10

static unsigned
parse_nsmequities_totalview_sequence_number_v30(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_sequence_number_v30, tvb, offset, NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_SIZE, NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_SIZE;
}

/* Sequenced Message Type values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT                                       'S'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY                                    'R'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION                               'H'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR 'Y'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION                        'L'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL                                 'V'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL                                  'W'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE                          'K'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR                                'J'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT                                   'h'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION                      'A'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION                    'F'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED                                     'E'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE                          'C'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL                                       'X'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE                                       'D'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE                                      'U'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE                                    'P'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE                                        'Q'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE                                       'B'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR                      'I'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR                 'N'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY  'O'
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP                                          'T'

/* Sequenced Message Type */
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NAME        "Sequenced Message Type"
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying sequenced message type"
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_FILTER      "nsmequities.totalview.sequencedmessagetype"
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SIZE        1

static const value_string nsmequities_totalview_sequenced_message_type_vals[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY, "Direct Listing With Capital Raise Price Discovery Message" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_sequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_sequenced_message_type, tvb, offset, NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SIZE;
}

/* Server Packet Type values the dispatch switches on */
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET            '+'
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET   'A'
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET   'J'
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET   'S'
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET 'H'
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET   'Z'

/* Server Packet Type */
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_NAME        "Server Packet Type"
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the server"
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_FILTER      "nsmequities.totalview.serverpackettype"
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SIZE        1

static const value_string nsmequities_totalview_server_packet_type_vals[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session Packet" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_server_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_server_packet_type, tvb, offset, NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SIZE;
}

/* Session */
#define NSMEQUITIES_TOTALVIEW_SESSION_NAME        "Session"
#define NSMEQUITIES_TOTALVIEW_SESSION_DESCRIPTION "Identity of the multicast session"
#define NSMEQUITIES_TOTALVIEW_SESSION_FILTER      "nsmequities.totalview.session"
#define NSMEQUITIES_TOTALVIEW_SESSION_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_SESSION_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_SESSION_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SESSION_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SESSION_SIZE        10

static unsigned
parse_nsmequities_totalview_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_session, tvb, offset, NSMEQUITIES_TOTALVIEW_SESSION_SIZE, NSMEQUITIES_TOTALVIEW_SESSION_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SESSION_SIZE;
}

/* Session V30 */
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_NAME        "Session"
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_DESCRIPTION "Identity of the multicast session the payload relates to"
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_FILTER      "nsmequities.totalview.session"
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SESSION_V30_SIZE        10

static unsigned
parse_nsmequities_totalview_session_v30(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_session_v30, tvb, offset, NSMEQUITIES_TOTALVIEW_SESSION_V30_SIZE, NSMEQUITIES_TOTALVIEW_SESSION_V30_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SESSION_V30_SIZE;
}

/* Session V10 */
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_NAME        "Session"
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_DESCRIPTION "The session ID of the session that is now logged into. Left padded with spaces."
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_FILTER      "nsmequities.totalview.session"
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SESSION_V10_SIZE        10

static unsigned
parse_nsmequities_totalview_session_v10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_session_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_SESSION_V10_SIZE, NSMEQUITIES_TOTALVIEW_SESSION_V10_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SESSION_V10_SIZE;
}

/* Shares */
#define NSMEQUITIES_TOTALVIEW_SHARES_NAME        "Shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_DESCRIPTION "The total number of shares associated with the order being added to the book"
#define NSMEQUITIES_TOTALVIEW_SHARES_FILTER      "nsmequities.totalview.shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_TOTALVIEW_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SHARES_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_SHARES_SIZE        4

static unsigned
parse_nsmequities_totalview_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_shares, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_SIZE, NSMEQUITIES_TOTALVIEW_SHARES_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SHARES_SIZE;
}

/* Shares V20a */
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_NAME        "Shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_DESCRIPTION "Total number of shares being added to the book (may be less than the number of shares entered)."
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_FILTER      "nsmequities.totalview.shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_SIZE        6

static unsigned
parse_nsmequities_totalview_shares_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_shares_v20a, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_SIZE;
}

/* Shares V10 */
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_NAME        "Shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_DESCRIPTION "Total number of shares being added to the book (may be less than the number of shares entered)."
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_FILTER      "nsmequities.totalview.shares"
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SHARES_V10_SIZE        9

static unsigned
parse_nsmequities_totalview_shares_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_V10_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_shares_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_V10_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_SHARES_V10_SIZE;
}

/* Shares Numeric 6 */
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_NAME        "Shares Numeric 6"
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_DESCRIPTION "The total number of shares associated with the order being added to the book."
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_FILTER      "nsmequities.totalview.sharesnumeric6"
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_SIZE        6

static unsigned
parse_nsmequities_totalview_shares_numeric_6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_shares_numeric_6, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_SIZE;
}

/* Shares Numeric 9 */
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_NAME        "Shares Numeric 9"
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_DESCRIPTION "The number of shares matched in the NASDAQ Cross."
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_FILTER      "nsmequities.totalview.sharesnumeric9"
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_TYPE        FT_UINT64
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_SIZE        9

static unsigned
parse_nsmequities_totalview_shares_numeric_9(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_totalview_shares_numeric_9, tvb, offset, NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_SIZE, value);

    return offset + NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_SIZE;
}

/* Short Sale Threshold Indicator */
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_NAME        "Short Sale Threshold Indicator"
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_DESCRIPTION "Indicates if a security is subject to mandatory close-out of short sales under SEC Rule 203(b)(3)."
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_FILTER      "nsmequities.totalview.shortsalethresholdindicator"
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_SIZE        1

static const value_string nsmequities_totalview_short_sale_threshold_indicator_vals[] = {
    { 'Y', "Restricted" },
    { 'N', "Not Restricted" },
    { ' ', "Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_short_sale_threshold_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_short_sale_threshold_indicator, tvb, offset, NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_SIZE, NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_SIZE;
}

/* Side */
#define NSMEQUITIES_TOTALVIEW_SIDE_NAME        "Side"
#define NSMEQUITIES_TOTALVIEW_SIDE_DESCRIPTION "The type of order being added."
#define NSMEQUITIES_TOTALVIEW_SIDE_FILTER      "nsmequities.totalview.side"
#define NSMEQUITIES_TOTALVIEW_SIDE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_SIDE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_SIDE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_SIDE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_SIDE_SIZE        1

static const value_string nsmequities_totalview_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_side, tvb, offset, NSMEQUITIES_TOTALVIEW_SIDE_SIZE, NSMEQUITIES_TOTALVIEW_SIDE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_SIDE_SIZE;
}

/* Stock */
#define NSMEQUITIES_TOTALVIEW_STOCK_NAME        "Stock"
#define NSMEQUITIES_TOTALVIEW_STOCK_DESCRIPTION "Denotes the security symbol for the issue in the NASDAQ execution system."
#define NSMEQUITIES_TOTALVIEW_STOCK_FILTER      "nsmequities.totalview.stock"
#define NSMEQUITIES_TOTALVIEW_STOCK_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_SIZE        8

static unsigned
parse_nsmequities_totalview_stock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_SIZE;
}

/* Stock V40 */
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_NAME        "Stock"
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_DESCRIPTION "Denotes the security symbol for the issue in NASDAQ Single Book. Refer to Appendix NASDAQ Single Book stock symbol convention information."
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_FILTER      "nsmequities.totalview.stock"
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_V40_SIZE        6

static unsigned
parse_nsmequities_totalview_stock_v40(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_v40, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_V40_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_V40_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_V40_SIZE;
}

/* Stock Alpha 6 */
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_NAME        "Stock Alpha 6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_DESCRIPTION "Denotes the security symbol for the issue in NASDAQ Single Book. Refer to Appendix B for NASDAQ Single Book stock symbol convention information."
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_FILTER      "nsmequities.totalview.stockalpha6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_SIZE        6

static unsigned
parse_nsmequities_totalview_stock_alpha_6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_alpha_6, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_SIZE;
}

/* Stock Alpha 8 */
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_NAME        "Stock Alpha 8"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_DESCRIPTION "Denotes the security symbol for the issue in the NASDAQ execution system. Refer to Appendix B for stock symbol convention information."
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_FILTER      "nsmequities.totalview.stockalpha8"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_SIZE        8

static unsigned
parse_nsmequities_totalview_stock_alpha_8(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_alpha_8, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_SIZE;
}

/* Stock Alphabetic 6 */
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_NAME        "Stock Alphabetic 6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_DESCRIPTION "Denotes the security symbol for the issue in NASDAQ Single Book."
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_FILTER      "nsmequities.totalview.stockalphabetic6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_SIZE        6

static unsigned
parse_nsmequities_totalview_stock_alphabetic_6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_alphabetic_6, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_SIZE;
}

/* Stock Alphanumeric 6 */
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_NAME        "Stock Alphanumeric 6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_DESCRIPTION "Denotes the security symbol for which the position is being generated."
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_FILTER      "nsmequities.totalview.stockalphanumeric6"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_SIZE        6

static unsigned
parse_nsmequities_totalview_stock_alphanumeric_6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_alphanumeric_6, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_SIZE;
}

/* Stock Alphanumeric 8 */
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_NAME        "Stock Alphanumeric 8"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_DESCRIPTION "Denotes the security symbol for which the position is being generated."
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_FILTER      "nsmequities.totalview.stockalphanumeric8"
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_SIZE        8

static unsigned
parse_nsmequities_totalview_stock_alphanumeric_8(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_alphanumeric_8, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_SIZE;
}

/* Stock Halted */
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_NAME        "Stock Halted"
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_DESCRIPTION "Indicates if the stock symbol is halted on NASDAQ system."
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_FILTER      "nsmequities.totalview.stockhalted"
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_STOCK_HALTED_SIZE        1

static const value_string nsmequities_totalview_stock_halted_vals[] = {
    { 'T', "Halted" },
    { 'F', "Trading" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_stock_halted(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_halted, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_HALTED_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_HALTED_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_HALTED_SIZE;
}

/* Stock Locate */
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_NAME        "Stock Locate"
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_DESCRIPTION "Locate Code uniquely assigned to the security symbol for the day"
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_FILTER      "nsmequities.totalview.stocklocate"
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_SIZE        2

static unsigned
parse_nsmequities_totalview_stock_locate(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_stock_locate, tvb, offset, NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_SIZE, NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_SIZE;
}

/* Text */
#define NSMEQUITIES_TOTALVIEW_TEXT_NAME        "Text"
#define NSMEQUITIES_TOTALVIEW_TEXT_DESCRIPTION "Free form human readable text"
#define NSMEQUITIES_TOTALVIEW_TEXT_FILTER      "nsmequities.totalview.text"
#define NSMEQUITIES_TOTALVIEW_TEXT_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_TEXT_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_TEXT_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TEXT_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_TEXT_SIZE        1

static unsigned
parse_nsmequities_totalview_text(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_text, tvb, offset, NSMEQUITIES_TOTALVIEW_TEXT_SIZE, NSMEQUITIES_TOTALVIEW_TEXT_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_TEXT_SIZE;
}

/* Timestamp */
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_NAME        "Timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_DESCRIPTION "Nanoseconds since midnight"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_FILTER      "nsmequities.totalview.timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE        6

static unsigned
parse_nsmequities_totalview_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t counted = tvb_get_ntoh48(tvb, offset);

    if (!nsmequities_totalview_pref_read_timestamp) {
        proto_tree_add_uint64(tree, hf_nsmequities_totalview_elapsed_nanoseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE, counted);

        return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(counted / 1000000000),
        .nsecs = (int)(counted % 1000000000) * 1,
    };

    nstime_t instant;

    nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_timestamp, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

    char clock[32];

    nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_nanoseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE, counted);

    return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_SIZE;
}

/* Timestamp V20a */
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_NAME        "Timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_DESCRIPTION "Milliseconds past midnight Eastern the message was generated"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_FILTER      "nsmequities.totalview.timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE        8

static unsigned
parse_nsmequities_totalview_timestamp_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, ENC_ASCII);

    uint64_t counted = (uint64_t)strtoull(text, NULL, 10);

    if (!nsmequities_totalview_pref_read_timestamp) {
        proto_tree_add_uint64(tree, hf_nsmequities_totalview_elapsed_milliseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, counted);

        return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(counted / 1000),
        .nsecs = (int)(counted % 1000) * 1000000,
    };

    nstime_t instant;

    nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_timestamp_v20a, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

    char clock[32];

    nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_milliseconds, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE, counted);

    return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_SIZE;
}

/* Timestamp V10 */
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_NAME        "Timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_DESCRIPTION "Hundredths of a second past midnight Eastern the message was generated"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_FILTER      "nsmequities.totalview.timestamp"
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE        7

static unsigned
parse_nsmequities_totalview_timestamp_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, ENC_ASCII);

    uint64_t counted = (uint64_t)strtoull(text, NULL, 10);

    if (!nsmequities_totalview_pref_read_timestamp) {
        proto_tree_add_uint64(tree, hf_nsmequities_totalview_elapsed_hundredths, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, counted);

        return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(counted / 100),
        .nsecs = (int)(counted % 100) * 10000000,
    };

    nstime_t instant;

    nsmequities_totalview_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_totalview_timestamp_v10, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_totalview_timestamp);

    char clock[32];

    nsmequities_totalview_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_totalview_time_of_day, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_totalview_local, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_totalview_elapsed_hundredths, tvb, offset, NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE, counted);

    return offset + NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_SIZE;
}

/* Tracking Number */
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_NAME        "Tracking Number"
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_DESCRIPTION "Nasdaq internal tracking number"
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_FILTER      "nsmequities.totalview.trackingnumber"
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_TYPE        FT_UINT16
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_SIZE        2

static unsigned
parse_nsmequities_totalview_tracking_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_tracking_number, tvb, offset, NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_SIZE, NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_SIZE;
}

/* Trading State */
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_NAME        "Trading State"
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_DESCRIPTION "Indicates the current trading state for the stock"
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_FILTER      "nsmequities.totalview.tradingstate"
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_TRADING_STATE_SIZE        1

static const value_string nsmequities_totalview_trading_state_vals[] = {
    { 'H', "Halted" },
    { 'P', "Paused" },
    { 'Q', "Quotation Only Period" },
    { 'T', "Trading" },
    { 'V', "Halted Or Paused On Nasdaq" },
    { 'R', "Quotation Only Period On Nasdaq" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_totalview_trading_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_trading_state, tvb, offset, NSMEQUITIES_TOTALVIEW_TRADING_STATE_SIZE, NSMEQUITIES_TOTALVIEW_TRADING_STATE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_TRADING_STATE_SIZE;
}

/* Unsequenced Message */
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_NAME        "Unsequenced Message"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_DESCRIPTION "The unsequenced (client to server) message carried by the packet, opaque bytes unless an application source dispatches it"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_FILTER      "nsmequities.totalview.unsequencedmessage"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE        FT_BYTES
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_ENCODING    ENC_NA

/* Unsequenced Message Type */
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_NAME        "Unsequenced Message Type"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying unsequenced message type"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_FILTER      "nsmequities.totalview.unsequencedmessagetype"
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_SIZE        1

static unsigned
parse_nsmequities_totalview_unsequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_unsequenced_message_type, tvb, offset, NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_SIZE, NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_SIZE;
}

/* Upper Auction Collar Price */
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_NAME        "Upper Auction Collar Price"
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_DESCRIPTION "Indicates the price of the upper auction collar threshold"
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_FILTER      "nsmequities.totalview.upperauctioncollarprice"
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_SIZE        4

static unsigned
parse_nsmequities_totalview_upper_auction_collar_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_upper_auction_collar_price, tvb, offset, NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_SIZE, NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_SIZE;
}

/* Upper Price Range Collar */
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_NAME        "Upper Price Range Collar"
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_DESCRIPTION "Indicates the price of the Upper Auction Collar Threshold"
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_FILTER      "nsmequities.totalview.upperpricerangecollar"
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_TYPE        FT_INT32
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_SIZE        4

static unsigned
parse_nsmequities_totalview_upper_price_range_collar(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_upper_price_range_collar, tvb, offset, NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_SIZE, NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_SIZE;
}

/* Username */
#define NSMEQUITIES_TOTALVIEW_USERNAME_NAME        "Username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_DESCRIPTION "Session username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_FILTER      "nsmequities.totalview.username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_USERNAME_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_USERNAME_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_USERNAME_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_USERNAME_SIZE        6

static unsigned
parse_nsmequities_totalview_username(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_username, tvb, offset, NSMEQUITIES_TOTALVIEW_USERNAME_SIZE, NSMEQUITIES_TOTALVIEW_USERNAME_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_USERNAME_SIZE;
}

/* Username V32 */
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_NAME        "Username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_DESCRIPTION "Session username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_FILTER      "nsmequities.totalview.username"
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_TYPE        FT_STRING
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_DISPLAY     BASE_NONE
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_MASK        0x0
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_ENCODING    ENC_ASCII
#define NSMEQUITIES_TOTALVIEW_USERNAME_V32_SIZE        6

static unsigned
parse_nsmequities_totalview_username_v32(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_totalview_username_v32, tvb, offset, NSMEQUITIES_TOTALVIEW_USERNAME_V32_SIZE, NSMEQUITIES_TOTALVIEW_USERNAME_V32_ENCODING);

    return offset + NSMEQUITIES_TOTALVIEW_USERNAME_V32_SIZE;
}

/*
 * NsmEquities TotalView Structs
 */

/* Message and group dissect methods */
static unsigned dissect_nsmequities_totalview_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_debug_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_mwcb_decline_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_mwcb_status_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_ipo_quoting_period_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_luld_auction_collar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_operational_halt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_non_cross_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_retail_price_improvement_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_direct_listing_with_capital_raise_price_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_request_packet_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_accepted_packet_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_retail_interest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_retail_price_improvement_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_debug_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_request_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_unsequenced_data_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_accepted_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_seconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_milliseconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_retail_price_improvement_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_retail_price_improvement_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_display(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v31f_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_replace_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_display_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_request_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_accepted_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_with_mpid_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_message_header_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_directory_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_trading_action_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_market_participant_position_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_with_price_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_delete_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_cross_trade_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_net_order_imbalance_indicator_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_message_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_stock_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_message_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_system_event_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_broken_trade_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_login_accepted_packet_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_data_packet_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_sequenced_message_header_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_add_order_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_executed_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_order_cancel_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_trade_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_totalview_client_packet_client_payload_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_totalview_client_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_totalview_client_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_packet_server_payload_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_server_payload_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_totalview_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_sequenced_message_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
static unsigned dissect_nsmequities_totalview_packet_payload_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);

/* Client Packet Header */
static unsigned
dissect_nsmequities_totalview_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_client_packet_header, &item, "Client Packet Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_packet_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_client_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Debug Packet */
static unsigned
dissect_nsmequities_totalview_debug_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_debug_text(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_nsmequities_totalview_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_username(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_password(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Unsequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_unsequenced_message_type(tvb, pinfo, tree, offset);
    /* Unsequenced Message is a placeholder, it consumes no bytes */

    return offset;
}

/* Server Packet Header */
static unsigned
dissect_nsmequities_totalview_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_server_packet_header, &item, "Server Packet Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_packet_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_server_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_totalview_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_accepted_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_accepted_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Rejected Packet */
static unsigned
dissect_nsmequities_totalview_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_reject_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* System Event Message */
static unsigned
dissect_nsmequities_totalview_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message */
static unsigned
dissect_nsmequities_totalview_stock_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_issue_classification(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_issue_sub_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_authenticity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_short_sale_threshold_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_ipo_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_luld_reference_price_tier(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_etp_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_etp_leverage_factor(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_inverse_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message */
static unsigned
dissect_nsmequities_totalview_stock_trading_action(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Reg Sho Short Sale Price Test Restricted Indicator Message */
static unsigned
dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_locate_code(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reg_sho_action(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message */
static unsigned
dissect_nsmequities_totalview_market_participant_position(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Mwcb Decline Level Message */
static unsigned
dissect_nsmequities_totalview_mwcb_decline_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_level_1(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_level_2(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_level_3(tvb, pinfo, tree, offset);

    return offset;
}

/* Mwcb Status Level Message */
static unsigned
dissect_nsmequities_totalview_mwcb_status_level(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_breached_level(tvb, pinfo, tree, offset);

    return offset;
}

/* Ipo Quoting Period Update */
static unsigned
dissect_nsmequities_totalview_ipo_quoting_period_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_ipo_quotation_release_time(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_ipo_quotation_release_qualifier(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_ipo_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Luld Auction Collar Message */
static unsigned
dissect_nsmequities_totalview_luld_auction_collar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_auction_collar_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_upper_auction_collar_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_lower_auction_collar_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_auction_collar_extension(tvb, pinfo, tree, offset);

    return offset;
}

/* Operational Halt Message */
static unsigned
dissect_nsmequities_totalview_operational_halt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_code(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_operational_halt_action(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order No Mpid Attribution Message */
static unsigned
dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Attribution Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_nsmequities_totalview_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message */
static unsigned
dissect_nsmequities_totalview_order_cancel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message */
static unsigned
dissect_nsmequities_totalview_order_delete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message */
static unsigned
dissect_nsmequities_totalview_order_replace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_original_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Non Cross Trade Message */
static unsigned
dissect_nsmequities_totalview_non_cross_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message */
static unsigned
dissect_nsmequities_totalview_cross_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message */
static unsigned
dissect_nsmequities_totalview_broken_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Price Improvement Indicator Message */
static unsigned
dissect_nsmequities_totalview_retail_price_improvement_indicator(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_interest_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* Direct Listing With Capital Raise Price Discovery Message */
static unsigned
dissect_nsmequities_totalview_direct_listing_with_capital_raise_price_discovery(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_open_eligibility_status(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_minimum_allowable_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_maximum_allowable_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_execution_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_execution_time(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_lower_price_range_collar(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_upper_price_range_collar(tvb, pinfo, tree, offset);

    return offset;
}

/* Message Header */
static unsigned
dissect_nsmequities_totalview_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_message_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_nsmequities_totalview_login_request_packet_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_username(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_password(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_sequence_number_v502023(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_totalview_login_accepted_packet_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_accepted_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_accepted_sequence_number_v502023(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v502022(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v502017(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* Retail Interest Message */
static unsigned
dissect_nsmequities_totalview_retail_interest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_locate(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_tracking_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_interest_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v41(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* Timestamp Message */
static unsigned
dissect_nsmequities_totalview_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_second(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message V41 */
static unsigned
dissect_nsmequities_totalview_system_event_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V41 */
static unsigned
dissect_nsmequities_totalview_stock_directory_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V41 */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Reg Sho Short Sale Price Test Restricted Indicator Message V41 */
static unsigned
dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reg_sho_action(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V41 */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V41 */
static unsigned
dissect_nsmequities_totalview_order_executed_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V41 */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V41 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V41 */
static unsigned
dissect_nsmequities_totalview_order_delete_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V41 */
static unsigned
dissect_nsmequities_totalview_order_replace_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_original_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V41 */
static unsigned
dissect_nsmequities_totalview_cross_trade_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V41 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V41 */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Price Improvement Indicator Message V41 */
static unsigned
dissect_nsmequities_totalview_retail_price_improvement_indicator_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_interest_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* Debug Packet */
static unsigned
dissect_nsmequities_totalview_debug_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_text(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_nsmequities_totalview_login_request_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_username_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_password_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_session_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_sequence_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Unsequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_unsequenced_data_packet_v32(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, unsigned offset)
{
    /* Unsequenced Message is a placeholder, it consumes no bytes */

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_totalview_login_accepted_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v32(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Sequenced Message Header */
static unsigned
dissect_nsmequities_totalview_sequenced_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_sequenced_message_header, &item, "Sequenced Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Seconds Message */
static unsigned
dissect_nsmequities_totalview_seconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_second_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Milliseconds Message */
static unsigned
dissect_nsmequities_totalview_milliseconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_millisecond(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message */
static unsigned
dissect_nsmequities_totalview_system_event_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message */
static unsigned
dissect_nsmequities_totalview_stock_directory_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Reg Sho Short Sale Price Test Restricted Indicator Message */
static unsigned
dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reg_sho_action(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_nsmequities_totalview_order_executed_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message */
static unsigned
dissect_nsmequities_totalview_order_cancel_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message */
static unsigned
dissect_nsmequities_totalview_order_delete_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message */
static unsigned
dissect_nsmequities_totalview_order_replace_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_original_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message */
static unsigned
dissect_nsmequities_totalview_cross_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message */
static unsigned
dissect_nsmequities_totalview_broken_trade_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Price Improvement Indicator Message */
static unsigned
dissect_nsmequities_totalview_retail_price_improvement_indicator_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_interest_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message V32 */
static unsigned
dissect_nsmequities_totalview_system_event_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V32 */
static unsigned
dissect_nsmequities_totalview_stock_directory_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V32 */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Reg Sho Short Sale Price Test Restricted Indicator Message V32 */
static unsigned
dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reg_sho_action(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V32 */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V32 */
static unsigned
dissect_nsmequities_totalview_order_executed_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V32 */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V32 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V32 */
static unsigned
dissect_nsmequities_totalview_order_delete_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V32 */
static unsigned
dissect_nsmequities_totalview_order_replace_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_original_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V32 */
static unsigned
dissect_nsmequities_totalview_cross_trade_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V32 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V32 */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Retail Price Improvement Indicator Message V32 */
static unsigned
dissect_nsmequities_totalview_retail_price_improvement_indicator_v32_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_8(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_interest_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v40(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* System Event Message V40 */
static unsigned
dissect_nsmequities_totalview_system_event_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V40 */
static unsigned
dissect_nsmequities_totalview_stock_directory_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V40 */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V40 */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V40 */
static unsigned
dissect_nsmequities_totalview_order_executed_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V40 */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V40 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V40 */
static unsigned
dissect_nsmequities_totalview_order_delete_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V40 */
static unsigned
dissect_nsmequities_totalview_order_replace_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_original_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V40 */
static unsigned
dissect_nsmequities_totalview_cross_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V40 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V40 */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v31(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Stock Directory Message */
static unsigned
dissect_nsmequities_totalview_stock_directory_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message */
static unsigned
dissect_nsmequities_totalview_cross_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message V31 */
static unsigned
dissect_nsmequities_totalview_system_event_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V31 */
static unsigned
dissect_nsmequities_totalview_stock_directory_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V31 */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V31 */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V31 */
static unsigned
dissect_nsmequities_totalview_order_executed_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V31 */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V31 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V31 */
static unsigned
dissect_nsmequities_totalview_order_delete_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V31 */
static unsigned
dissect_nsmequities_totalview_order_replace_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_original_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V31 */
static unsigned
dissect_nsmequities_totalview_cross_trade_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V31 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V31 */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v31_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v31f(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message */
static unsigned
dissect_nsmequities_totalview_order_replace_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_original_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Display Message */
static unsigned
dissect_nsmequities_totalview_order_display(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message V31f */
static unsigned
dissect_nsmequities_totalview_system_event_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V31f */
static unsigned
dissect_nsmequities_totalview_stock_directory_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V31f */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V31f */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V31f */
static unsigned
dissect_nsmequities_totalview_order_executed_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V31f */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V31f */
static unsigned
dissect_nsmequities_totalview_order_cancel_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V31f */
static unsigned
dissect_nsmequities_totalview_order_delete_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V31f */
static unsigned
dissect_nsmequities_totalview_order_replace_v31f_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_original_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V31f */
static unsigned
dissect_nsmequities_totalview_cross_trade_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V31f */
static unsigned
dissect_nsmequities_totalview_broken_trade_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V31f */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alpha_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_totalview_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v40f(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* System Event Message V40f */
static unsigned
dissect_nsmequities_totalview_system_event_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V40f */
static unsigned
dissect_nsmequities_totalview_stock_directory_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V40f */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V40f */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V40f */
static unsigned
dissect_nsmequities_totalview_order_executed_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V40f */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V40f */
static unsigned
dissect_nsmequities_totalview_order_cancel_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V40f */
static unsigned
dissect_nsmequities_totalview_order_delete_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replace Message V40f */
static unsigned
dissect_nsmequities_totalview_order_replace_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_original_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_new_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Display Message */
static unsigned
dissect_nsmequities_totalview_order_display_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V40f */
static unsigned
dissect_nsmequities_totalview_cross_trade_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V40f */
static unsigned
dissect_nsmequities_totalview_broken_trade_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V40f */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_paired_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_nsmequities_totalview_login_request_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_username_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_password_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_session_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_requested_sequence_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_totalview_login_accepted_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_session_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_sequence_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_totalview_sequenced_message_v30(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Stock Directory Message */
static unsigned
dissect_nsmequities_totalview_stock_directory_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alphabetic_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Add Order With Mpid Message */
static unsigned
dissect_nsmequities_totalview_add_order_with_mpid_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_attribution(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_nsmequities_totalview_order_executed_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message */
static unsigned
dissect_nsmequities_totalview_order_cancel_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message */
static unsigned
dissect_nsmequities_totalview_order_delete_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_numeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message */
static unsigned
dissect_nsmequities_totalview_cross_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message */
static unsigned
dissect_nsmequities_totalview_broken_trade_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Message Header */
static unsigned
dissect_nsmequities_totalview_message_header_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_message_header_v30, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* System Event Message V30 */
static unsigned
dissect_nsmequities_totalview_system_event_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Directory Message V30 */
static unsigned
dissect_nsmequities_totalview_stock_directory_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alphabetic_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_category(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_financial_status_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lot_size_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_round_lots_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Trading Action Message V30 */
static unsigned
dissect_nsmequities_totalview_stock_trading_action_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_trading_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reserved(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Market Participant Position Message V30 */
static unsigned
dissect_nsmequities_totalview_market_participant_position_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_mpid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_primary_market_maker(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_maker_mode(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_market_participant_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V30 */
static unsigned
dissect_nsmequities_totalview_order_executed_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed With Price Message V30 */
static unsigned
dissect_nsmequities_totalview_order_executed_with_price_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_printable(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_execution_price_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V30 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Delete Message V30 */
static unsigned
dissect_nsmequities_totalview_order_delete_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Cross Trade Message V30 */
static unsigned
dissect_nsmequities_totalview_cross_trade_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_shares_numeric_9(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V30 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Net Order Imbalance Indicator Message V30 */
static unsigned
dissect_nsmequities_totalview_net_order_imbalance_indicator_v30_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_paired_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_imbalance_direction(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_alphanumeric_6(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_far_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_near_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_current_reference_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_variation_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header_v20a(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start + 8);

    offset = dissect_nsmequities_totalview_sequenced_message_v20a(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Sequenced Message Header */
static unsigned
dissect_nsmequities_totalview_sequenced_message_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_sequenced_message_header_v20a, &item, "Sequenced Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_timestamp_v20a(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_v20a(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_mmid(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_v20a(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Stock Halt Status Message */
static unsigned
dissect_nsmequities_totalview_stock_halt_status(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_halted(tvb, pinfo, tree, offset);

    return offset;
}

/* Message Header */
static unsigned
dissect_nsmequities_totalview_message_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_message_header_v20a, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_timestamp_v20a(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* System Event Message V20a */
static unsigned
dissect_nsmequities_totalview_system_event_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V20a */
static unsigned
dissect_nsmequities_totalview_order_executed_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V20a */
static unsigned
dissect_nsmequities_totalview_order_cancel_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V20a */
static unsigned
dissect_nsmequities_totalview_broken_trade_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header_v20a(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start + 8);

    offset = dissect_nsmequities_totalview_sequenced_message_v20(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_v20a(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message V20 */
static unsigned
dissect_nsmequities_totalview_system_event_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message V20 */
static unsigned
dissect_nsmequities_totalview_order_executed_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v32(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message V20 */
static unsigned
dissect_nsmequities_totalview_order_cancel_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v32(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V20 */
static unsigned
dissect_nsmequities_totalview_broken_trade_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_totalview_login_accepted_packet_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_session_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_sequence_number_v30(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_totalview_sequenced_data_packet_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = dissect_nsmequities_totalview_sequenced_message_header_v10(tvb, pinfo, tree, offset);

    uint32_t message_type = tvb_get_uint8(tvb, start + 7);

    offset = dissect_nsmequities_totalview_sequenced_message_v10(tvb, pinfo, tree, offset, message_type);

    return offset;
}

/* Sequenced Message Header */
static unsigned
dissect_nsmequities_totalview_sequenced_message_header_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_totalview_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_totalview_sequenced_message_header_v10, &item, "Sequenced Message Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_totalview_timestamp_v10(tvb, pinfo, group, offset);
    offset = parse_nsmequities_totalview_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Add Order Message */
static unsigned
dissect_nsmequities_totalview_add_order_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_display(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_nsmequities_totalview_order_executed_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_executed_shares_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_contra_broker_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Cancel Message */
static unsigned
dissect_nsmequities_totalview_order_cancel_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_canceled_shares_v10(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Message */
static unsigned
dissect_nsmequities_totalview_trade_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_totalview_order_reference_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_shares_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_stock_v40(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_price_v10(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_match_number_v30(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_totalview_contra_broker_code(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * NsmEquities TotalView Parse Trees, a dispatch per distinct branch definition
 */

static const value_string nsmequities_totalview_client_packet_messages[] = {
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request Packet" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_totalview_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_totalview_client_packet_messages, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_totalview_login_request_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_unsequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat Packet */
        return offset;
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request Packet */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_client_packet_messages_v502023[] = {
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_totalview_client_packet_client_payload_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_totalview_client_packet_messages_v502023, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_totalview_login_request_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_unsequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_client_payload_messages_v32[] = {
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_totalview_client_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_totalview_client_payload_messages_v32, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_totalview_login_request_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_unsequenced_data_packet_v32(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_client_payload_messages_v30[] = {
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_totalview_client_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_totalview_client_payload_messages_v30, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_totalview_login_request_packet_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_unsequenced_data_packet_v32(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat Packet */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session Packet */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v502023[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v502023(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v502023, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v502022[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v502022, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v502022(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v502017[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v502017, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v502017(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v41[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v41, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v32[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v32, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v32(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v40[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v40, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v31[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v31, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v31(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v31f[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v31f, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v31f(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_packet_messages_v40f[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_packet_server_payload_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_packet_messages_v40f, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v502023(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v30[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v30, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v30(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v20a[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v20a, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v20a(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v20[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v20, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v20(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_server_payload_messages_v10[] = {
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_totalview_server_payload_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_totalview_server_payload_messages_v10, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_totalview_debug_packet_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_totalview_login_accepted_packet_v10(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_totalview_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_totalview_sequenced_data_packet_v10(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY, "Direct Listing With Capital Raise Price Discovery Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT:
        return dissect_nsmequities_totalview_operational_halt(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY:
        return dissect_nsmequities_totalview_direct_listing_with_capital_raise_price_discovery(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v502022[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages_v502022, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT:
        return dissect_nsmequities_totalview_operational_halt(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v502017[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Interest Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages_v502017, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_interest(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v41[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages_v41, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator_v41(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v32[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v32, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator_v32(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v40[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages_v40, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v40(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v31[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v31, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v31(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v31f[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Order Display Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v31f, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_order_display(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v31(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v40f[] = {
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Order Display Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_totalview_sequenced_message_messages_v40f, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_order_display_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v40f(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v30[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v30, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v30(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v20a[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Halt Status Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v20a, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_halt_status(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v20[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v20, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v20(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v30(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_sequenced_message_messages_v10[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_sequenced_message_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, message_type, nsmequities_totalview_sequenced_message_messages_v10, "Unknown (%u)"));

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v10(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v10(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v10(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v10(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v30(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY, "Direct Listing With Capital Raise Price Discovery Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT:
        return dissect_nsmequities_totalview_operational_halt(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY:
        return dissect_nsmequities_totalview_direct_listing_with_capital_raise_price_discovery(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v502022[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT, "Operational Halt Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v502022(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT:
        return dissect_nsmequities_totalview_operational_halt(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v502017[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Mwcb Decline Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL, "Mwcb Status Level Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE, "Ipo Quoting Period Update" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR, "Luld Auction Collar Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order No Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Attribution Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Non Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Interest Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v502017(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_mwcb_decline_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return dissect_nsmequities_totalview_mwcb_status_level(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return dissect_nsmequities_totalview_ipo_quoting_period_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return dissect_nsmequities_totalview_luld_auction_collar(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_no_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_attribution(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_non_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_interest(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v41[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v41(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v41(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator_v41(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v32[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR, "Reg Sho Short Sale Price Test Restricted Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR, "Retail Price Improvement Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return dissect_nsmequities_totalview_reg_sho_short_sale_price_test_restricted_indicator_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v32_v32(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return dissect_nsmequities_totalview_retail_price_improvement_indicator_v32_v32(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v40[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v40(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v40(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v31[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v31(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v31_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v31_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v31_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v31_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v31_v31(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v31f[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Order Display Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v31f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v31f_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_order_display(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v31(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v31f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v31f(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v40f[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Timestamp Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE, "Order Replace Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL, "Order Display Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v40f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_timestamp(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return dissect_nsmequities_totalview_order_replace_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return dissect_nsmequities_totalview_order_display_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v40(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v40f(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v40f(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v30[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP, "Seconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS, "Milliseconds Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY, "Stock Directory Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Trading Action Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION, "Market Participant Position Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION, "Add Order With Mpid Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE, "Order Executed With Price Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE, "Order Delete Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE, "Cross Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR, "Net Order Imbalance Indicator Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return dissect_nsmequities_totalview_seconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return dissect_nsmequities_totalview_milliseconds(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return dissect_nsmequities_totalview_stock_directory_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_trading_action_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return dissect_nsmequities_totalview_market_participant_position_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_with_mpid_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return dissect_nsmequities_totalview_order_executed_with_price_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return dissect_nsmequities_totalview_order_delete_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return dissect_nsmequities_totalview_cross_trade_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v30_v30(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return dissect_nsmequities_totalview_net_order_imbalance_indicator_v30_v30(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v20a[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION, "Stock Halt Status Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return dissect_nsmequities_totalview_stock_halt_status(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_totalview_packet_messages_v20[] = {
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION, "Add Order Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL, "Order Cancel Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE, "Trade Message" },
    { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { 0, NULL }
};

/* Payload: dispatch on message_type */
static unsigned
dissect_nsmequities_totalview_packet_payload_v20(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_totalview_system_event_v20(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return dissect_nsmequities_totalview_add_order_v20(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_totalview_order_executed_v20(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return dissect_nsmequities_totalview_order_cancel_v20(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return dissect_nsmequities_totalview_trade_v20a(tvb, pinfo, tree, offset);
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_totalview_broken_trade_v20(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
nsmequities_totalview_client_packet_show(uint32_t client_packet_type)
{
    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return nsmequities_totalview_show_session_messages;
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return nsmequities_totalview_show_session_messages;
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return nsmequities_totalview_show_session_messages;
    }

    return true;
}

typedef struct nsmequities_totalview_client_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
} nsmequities_totalview_client_packet_parse;

static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v502026 = { nsmequities_totalview_client_packet_messages, dissect_nsmequities_totalview_client_packet_client_payload };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v502023 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v502022 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v502018 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v502017 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v41 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v32 = { nsmequities_totalview_client_payload_messages_v32, dissect_nsmequities_totalview_client_payload_v32 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v40 = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v31 = { nsmequities_totalview_client_payload_messages_v32, dissect_nsmequities_totalview_client_payload_v32 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v31f = { nsmequities_totalview_client_payload_messages_v32, dissect_nsmequities_totalview_client_payload_v32 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v40f = { nsmequities_totalview_client_packet_messages_v502023, dissect_nsmequities_totalview_client_packet_client_payload_v502023 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v30 = { nsmequities_totalview_client_payload_messages_v30, dissect_nsmequities_totalview_client_payload_v30 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v20a = { nsmequities_totalview_client_payload_messages_v30, dissect_nsmequities_totalview_client_payload_v30 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v20 = { nsmequities_totalview_client_payload_messages_v30, dissect_nsmequities_totalview_client_payload_v30 };
static const nsmequities_totalview_client_packet_parse nsmequities_totalview_client_packet_parse_v10 = { nsmequities_totalview_client_payload_messages_v30, dissect_nsmequities_totalview_client_payload_v30 };

/* Parse tree of the selected version */
static const nsmequities_totalview_client_packet_parse *
nsmequities_totalview_client_packet_parse_for(int version)
{
    switch (version) {
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023:
        return &nsmequities_totalview_client_packet_parse_v502023;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022:
        return &nsmequities_totalview_client_packet_parse_v502022;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018:
        return &nsmequities_totalview_client_packet_parse_v502018;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017:
        return &nsmequities_totalview_client_packet_parse_v502017;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_1:
        return &nsmequities_totalview_client_packet_parse_v41;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_2:
        return &nsmequities_totalview_client_packet_parse_v32;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0:
        return &nsmequities_totalview_client_packet_parse_v40;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1:
        return &nsmequities_totalview_client_packet_parse_v31;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1_f:
        return &nsmequities_totalview_client_packet_parse_v31f;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0_f:
        return &nsmequities_totalview_client_packet_parse_v40f;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_0:
        return &nsmequities_totalview_client_packet_parse_v30;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0_a:
        return &nsmequities_totalview_client_packet_parse_v20a;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0:
        return &nsmequities_totalview_client_packet_parse_v20;
    case NSMEQUITIES_TOTALVIEW_VERSION_1_0:
        return &nsmequities_totalview_client_packet_parse_v10;
    default:
        return &nsmequities_totalview_client_packet_parse_v502026;
    }
}

/* Show preference of the dispatched message */
static bool
nsmequities_totalview_server_packet_show(uint32_t server_packet_type)
{
    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return nsmequities_totalview_show_session_messages;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return nsmequities_totalview_show_session_messages;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return nsmequities_totalview_show_session_messages;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return nsmequities_totalview_show_session_messages;
    }

    return true;
}

typedef struct nsmequities_totalview_server_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
} nsmequities_totalview_server_packet_parse;

static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v502026 = { nsmequities_totalview_server_packet_messages, dissect_nsmequities_totalview_server_packet_server_payload };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v502023 = { nsmequities_totalview_server_packet_messages_v502023, dissect_nsmequities_totalview_server_packet_server_payload_v502023 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v502022 = { nsmequities_totalview_server_packet_messages_v502022, dissect_nsmequities_totalview_server_packet_server_payload_v502022 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v502018 = { nsmequities_totalview_server_packet_messages_v502022, dissect_nsmequities_totalview_server_packet_server_payload_v502022 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v502017 = { nsmequities_totalview_server_packet_messages_v502017, dissect_nsmequities_totalview_server_packet_server_payload_v502017 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v41 = { nsmequities_totalview_server_packet_messages_v41, dissect_nsmequities_totalview_server_packet_server_payload_v41 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v32 = { nsmequities_totalview_server_payload_messages_v32, dissect_nsmequities_totalview_server_payload_v32 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v40 = { nsmequities_totalview_server_packet_messages_v40, dissect_nsmequities_totalview_server_packet_server_payload_v40 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v31 = { nsmequities_totalview_server_payload_messages_v31, dissect_nsmequities_totalview_server_payload_v31 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v31f = { nsmequities_totalview_server_payload_messages_v31f, dissect_nsmequities_totalview_server_payload_v31f };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v40f = { nsmequities_totalview_server_packet_messages_v40f, dissect_nsmequities_totalview_server_packet_server_payload_v40f };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v30 = { nsmequities_totalview_server_payload_messages_v30, dissect_nsmequities_totalview_server_payload_v30 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v20a = { nsmequities_totalview_server_payload_messages_v20a, dissect_nsmequities_totalview_server_payload_v20a };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v20 = { nsmequities_totalview_server_payload_messages_v20, dissect_nsmequities_totalview_server_payload_v20 };
static const nsmequities_totalview_server_packet_parse nsmequities_totalview_server_packet_parse_v10 = { nsmequities_totalview_server_payload_messages_v10, dissect_nsmequities_totalview_server_payload_v10 };

/* Parse tree of the selected version */
static const nsmequities_totalview_server_packet_parse *
nsmequities_totalview_server_packet_parse_for(int version)
{
    switch (version) {
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023:
        return &nsmequities_totalview_server_packet_parse_v502023;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022:
        return &nsmequities_totalview_server_packet_parse_v502022;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018:
        return &nsmequities_totalview_server_packet_parse_v502018;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017:
        return &nsmequities_totalview_server_packet_parse_v502017;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_1:
        return &nsmequities_totalview_server_packet_parse_v41;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_2:
        return &nsmequities_totalview_server_packet_parse_v32;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0:
        return &nsmequities_totalview_server_packet_parse_v40;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1:
        return &nsmequities_totalview_server_packet_parse_v31;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1_f:
        return &nsmequities_totalview_server_packet_parse_v31f;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0_f:
        return &nsmequities_totalview_server_packet_parse_v40f;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_0:
        return &nsmequities_totalview_server_packet_parse_v30;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0_a:
        return &nsmequities_totalview_server_packet_parse_v20a;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0:
        return &nsmequities_totalview_server_packet_parse_v20;
    case NSMEQUITIES_TOTALVIEW_VERSION_1_0:
        return &nsmequities_totalview_server_packet_parse_v10;
    default:
        return &nsmequities_totalview_server_packet_parse_v502026;
    }
}

/* Show preference of the dispatched message */
static bool
nsmequities_totalview_packet_show(uint32_t message_type)
{
    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_DECLINE_LEVEL:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MWCB_STATUS_LEVEL:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_LULD_AUCTION_COLLAR:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_OPERATIONAL_HALT:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP:
        return nsmequities_totalview_show_application_messages;
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS:
        return nsmequities_totalview_show_application_messages;
    }

    return true;
}

static unsigned dissect_nsmequities_totalview_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_packet_header_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_packet_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_totalview_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const struct nsmequities_totalview_packet_parse *parse);
static unsigned dissect_nsmequities_totalview_packet_message_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const struct nsmequities_totalview_packet_parse *parse);
static unsigned dissect_nsmequities_totalview_packet_message_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const struct nsmequities_totalview_packet_parse *parse);
static uint32_t dissect_nsmequities_totalview_packet_count(tvbuff_t *tvb);
static uint32_t dissect_nsmequities_totalview_packet_count_v30(tvbuff_t *tvb);
static uint32_t dissect_nsmequities_totalview_packet_count_v20a(tvbuff_t *tvb);

typedef struct nsmequities_totalview_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
    unsigned (*header)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
    unsigned (*message)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const struct nsmequities_totalview_packet_parse *parse);
    uint32_t (*count)(tvbuff_t *tvb);
} nsmequities_totalview_packet_parse;

static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v502026 = { nsmequities_totalview_packet_messages, dissect_nsmequities_totalview_packet_payload, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v502023 = { nsmequities_totalview_packet_messages, dissect_nsmequities_totalview_packet_payload, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v502022 = { nsmequities_totalview_packet_messages_v502022, dissect_nsmequities_totalview_packet_payload_v502022, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v502018 = { nsmequities_totalview_packet_messages_v502022, dissect_nsmequities_totalview_packet_payload_v502022, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v502017 = { nsmequities_totalview_packet_messages_v502017, dissect_nsmequities_totalview_packet_payload_v502017, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v41 = { nsmequities_totalview_packet_messages_v41, dissect_nsmequities_totalview_packet_payload_v41, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v32 = { nsmequities_totalview_packet_messages_v32, dissect_nsmequities_totalview_packet_payload_v32, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v40 = { nsmequities_totalview_packet_messages_v40, dissect_nsmequities_totalview_packet_payload_v40, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v31 = { nsmequities_totalview_packet_messages_v31, dissect_nsmequities_totalview_packet_payload_v31, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v31f = { nsmequities_totalview_packet_messages_v31f, dissect_nsmequities_totalview_packet_payload_v31f, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v40f = { nsmequities_totalview_packet_messages_v40f, dissect_nsmequities_totalview_packet_payload_v40f, dissect_nsmequities_totalview_packet_header, dissect_nsmequities_totalview_packet_message, dissect_nsmequities_totalview_packet_count };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v30 = { nsmequities_totalview_packet_messages_v30, dissect_nsmequities_totalview_packet_payload_v30, dissect_nsmequities_totalview_packet_header_v30, dissect_nsmequities_totalview_packet_message_v30, dissect_nsmequities_totalview_packet_count_v30 };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v20a = { nsmequities_totalview_packet_messages_v20a, dissect_nsmequities_totalview_packet_payload_v20a, dissect_nsmequities_totalview_packet_header_v20a, dissect_nsmequities_totalview_packet_message_v20a, dissect_nsmequities_totalview_packet_count_v20a };
static const nsmequities_totalview_packet_parse nsmequities_totalview_packet_parse_v20 = { nsmequities_totalview_packet_messages_v20, dissect_nsmequities_totalview_packet_payload_v20, dissect_nsmequities_totalview_packet_header_v20a, dissect_nsmequities_totalview_packet_message_v20a, dissect_nsmequities_totalview_packet_count_v20a };

/* Parse tree of the selected version */
static const nsmequities_totalview_packet_parse *
nsmequities_totalview_packet_parse_for(int version)
{
    switch (version) {
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2023:
        return &nsmequities_totalview_packet_parse_v502023;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2022:
        return &nsmequities_totalview_packet_parse_v502022;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2018:
        return &nsmequities_totalview_packet_parse_v502018;
    case NSMEQUITIES_TOTALVIEW_VERSION_5_0_2017:
        return &nsmequities_totalview_packet_parse_v502017;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_1:
        return &nsmequities_totalview_packet_parse_v41;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_2:
        return &nsmequities_totalview_packet_parse_v32;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0:
        return &nsmequities_totalview_packet_parse_v40;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1:
        return &nsmequities_totalview_packet_parse_v31;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_1_f:
        return &nsmequities_totalview_packet_parse_v31f;
    case NSMEQUITIES_TOTALVIEW_VERSION_4_0_f:
        return &nsmequities_totalview_packet_parse_v40f;
    case NSMEQUITIES_TOTALVIEW_VERSION_3_0:
        return &nsmequities_totalview_packet_parse_v30;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0_a:
        return &nsmequities_totalview_packet_parse_v20a;
    case NSMEQUITIES_TOTALVIEW_VERSION_2_0:
        return &nsmequities_totalview_packet_parse_v20;
    default:
        return &nsmequities_totalview_packet_parse_v502026;
    }
}

/* Is the port the acceptor's, by preference or by the declared ports? */
static bool
nsmequities_totalview_acceptor_port(uint32_t port)
{
    return port != 0 && (port == nsmequities_totalview_pref_acceptor_port || port == 18070 || port == 26400 || port == 26477 || port == 18170);
}

/* Connection role of the frame's sender */
static int
nsmequities_totalview_role(packet_info *pinfo)
{
    if (nsmequities_totalview_pref_assume_role != NSMEQUITIES_TOTALVIEW_ROLE_RESOLVE) {
        return nsmequities_totalview_pref_assume_role;
    }

    if (nsmequities_totalview_acceptor_port(pinfo->destport)) {
        return NSMEQUITIES_TOTALVIEW_ROLE_INITIATOR;
    }

    if (nsmequities_totalview_acceptor_port(pinfo->srcport)) {
        return NSMEQUITIES_TOTALVIEW_ROLE_ACCEPTOR;
    }

    nsmequities_totalview_conversation *session = nsmequities_totalview_conversation_of(pinfo);

    bool first = pinfo->srcport == session->port
        && addresses_equal(&pinfo->src, &session->initiator);

    if (nsmequities_totalview_pref_swap_sides) {
        first = !first;
    }

    if (session->swapped) {
        first = !first;
    }

    return first ? NSMEQUITIES_TOTALVIEW_ROLE_INITIATOR : NSMEQUITIES_TOTALVIEW_ROLE_ACCEPTOR;
}

/* Swap the resolved sides of the frame's conversation */
static void
nsmequities_totalview_swap(packet_info *pinfo)
{
    nsmequities_totalview_conversation *session = nsmequities_totalview_conversation_of(pinfo);

    session->swapped = !session->swapped;
}

/* NsmEquities TotalView message size adjusts the declared length */
#define NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_totalview_client_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_client_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t client_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, client_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_totalview_client_packet_show(client_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_totalview_message, NULL, "%s ('%c')", name, (char)client_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_totalview_client_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, client_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_totalview_length);
    }

    return packet_length + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_nsmequities_totalview_client_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_client_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_nsmequities_totalview_client_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Client Packet: header then counted messages */
static int
dissect_nsmequities_totalview_client_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSMEQUITIES_TOTALVIEW_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_nsmequities_totalview, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_nsmequities_totalview);

    nsmequities_totalview_anchor_begin(pinfo);

    const nsmequities_totalview_endpoint *endpoint = nsmequities_totalview_endpoint_of(pinfo);

    proto_item_append_text(item, ", Client");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Client");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = nsmequities_totalview_version(seconds);

    proto_item_append_text(item, " %s", nsmequities_totalview_version_name(version));

    if (endpoint != NULL) {
        proto_item_append_text(item, ", %s", endpoint->name);
    }

    const nsmequities_totalview_client_packet_parse *parse = nsmequities_totalview_client_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_nsmequities_totalview_client_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* NsmEquities TotalView message size adjusts the declared length */
#define NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_totalview_server_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_server_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t server_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, server_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_totalview_server_packet_show(server_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_totalview_message, NULL, "%s ('%c')", name, (char)server_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_totalview_server_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, server_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_totalview_length);
    }

    return packet_length + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_nsmequities_totalview_server_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_server_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_nsmequities_totalview_server_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Server Packet: header then counted messages */
static int
dissect_nsmequities_totalview_server_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSMEQUITIES_TOTALVIEW_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_nsmequities_totalview, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_nsmequities_totalview);

    nsmequities_totalview_anchor_begin(pinfo);

    const nsmequities_totalview_endpoint *endpoint = nsmequities_totalview_endpoint_of(pinfo);

    proto_item_append_text(item, ", Server");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Server");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = nsmequities_totalview_version(seconds);

    proto_item_append_text(item, " %s", nsmequities_totalview_version_name(version));

    if (endpoint != NULL) {
        proto_item_append_text(item, ", %s", endpoint->name);
    }

    const nsmequities_totalview_server_packet_parse *parse = nsmequities_totalview_server_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_nsmequities_totalview_server_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* Packet Header */
static unsigned
dissect_nsmequities_totalview_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, NSMEQUITIES_TOTALVIEW_PACKET_HEADER_SIZE,
        ett_nsmequities_totalview_header, NULL, "Packet Header");

    offset = parse_nsmequities_totalview_session(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_sequence_number(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_message_count(tvb, pinfo, header, offset);

    return offset;
}

/* Packet Header */
static unsigned
dissect_nsmequities_totalview_packet_header_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, 16,
        ett_nsmequities_totalview_header, NULL, "Packet Header");

    offset = parse_nsmequities_totalview_session_v30(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_sequence(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_count(tvb, pinfo, header, offset);

    return offset;
}

/* Packet Header */
static unsigned
dissect_nsmequities_totalview_packet_header_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, 16,
        ett_nsmequities_totalview_header, NULL, "Packet Header");

    offset = parse_nsmequities_totalview_session_v30(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_sequence(tvb, pinfo, header, offset);
    offset = parse_nsmequities_totalview_count(tvb, pinfo, header, offset);

    return offset;
}

/* Messages the packet declares, as Packet states it */
static uint32_t
dissect_nsmequities_totalview_packet_count(tvbuff_t *tvb)
{
    return tvb_get_ntohs(tvb, 18);
}

/* Messages the packet declares, as Packet states it */
static uint32_t
dissect_nsmequities_totalview_packet_count_v30(tvbuff_t *tvb)
{
    return tvb_get_letohs(tvb, 14);
}

/* Messages the packet declares, as Packet states it */
static uint32_t
dissect_nsmequities_totalview_packet_count_v20a(tvbuff_t *tvb)
{
    return tvb_get_letohs(tvb, 14);
}

/* NsmEquities TotalView message size adjusts the declared length */
#define NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_totalview_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_packet_parse *parse)
{
    uint32_t message_length = tvb_get_ntohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_totalview_packet_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_totalview_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_totalview_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_totalview_length);
    }

    return message_length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT;
}

/* NsmEquities TotalView message size adjusts the declared length */
#define NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_totalview_packet_message_v30(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_packet_parse *parse)
{
    uint32_t length = tvb_get_ntohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_totalview_packet_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_totalview_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_totalview_message_header_v30(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_totalview_length);
    }

    return length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT;
}

/* NsmEquities TotalView message size adjusts the declared length */
#define NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_totalview_packet_message_v20a(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_totalview_packet_parse *parse)
{
    uint32_t length = tvb_get_ntohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 10);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_totalview_packet_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_totalview_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_totalview_message_header_v20a(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_totalview_length);
    }

    return length + NSMEQUITIES_TOTALVIEW_PACKET_MESSAGE_ADJUSTMENT;
}

/* Counted messages, returns the position after the last message */
static unsigned
dissect_nsmequities_totalview_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t count, const nsmequities_totalview_packet_parse *parse)
{
    for (uint32_t index = 0; index < count; index++) {
        offset += parse->message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_nsmequities_totalview_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSMEQUITIES_TOTALVIEW_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_nsmequities_totalview, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_nsmequities_totalview);

    nsmequities_totalview_anchor_begin(pinfo);

    const nsmequities_totalview_endpoint *endpoint = nsmequities_totalview_endpoint_of(pinfo);

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = nsmequities_totalview_version(seconds);

    proto_item_append_text(item, " %s", nsmequities_totalview_version_name(version));

    if (endpoint != NULL) {
        proto_item_append_text(item, ", %s", endpoint->name);
    }

    const nsmequities_totalview_packet_parse *parse = nsmequities_totalview_packet_parse_for(version);
    uint32_t count = parse->count(tvb);
    unsigned position = parse->header(tvb, pinfo, packet, 0);

    if (count == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Heartbeat");
        return tvb_captured_length(tvb);
    }

    if (count == 65535) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "End Of Session");
        return tvb_captured_length(tvb);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%u %s", count, count == 1 ? "Message" : "Messages");

    position = dissect_nsmequities_totalview_packet_messages(tvb, pinfo, packet, position, count, parse);

    return (int)position;
}

static bool nsmequities_totalview_client_packet_heur_fingerprint(tvbuff_t *tvb);
static bool nsmequities_totalview_server_packet_heur_fingerprint(tvbuff_t *tvb);

/* Packet: the side of the transport and the sender's connection role */
static int
dissect_nsmequities_totalview(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (pinfo->ptype == PT_TCP) {
        if (nsmequities_totalview_role(pinfo) == NSMEQUITIES_TOTALVIEW_ROLE_INITIATOR) {
            if (!nsmequities_totalview_client_packet_heur_fingerprint(tvb) && nsmequities_totalview_server_packet_heur_fingerprint(tvb)) {
                nsmequities_totalview_swap(pinfo);

                return dissect_nsmequities_totalview_server_packet(tvb, pinfo, tree, data);
            }

            return dissect_nsmequities_totalview_client_packet(tvb, pinfo, tree, data);
        }

        if (!nsmequities_totalview_server_packet_heur_fingerprint(tvb) && nsmequities_totalview_client_packet_heur_fingerprint(tvb)) {
            nsmequities_totalview_swap(pinfo);

            return dissect_nsmequities_totalview_client_packet(tvb, pinfo, tree, data);
        }

        return dissect_nsmequities_totalview_server_packet(tvb, pinfo, tree, data);
    }

    return dissect_nsmequities_totalview_packet(tvb, pinfo, tree, data);
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define NSMEQUITIES_TOTALVIEW_MINIMUM_SIZE 1

/* The frame was sent to an endpoint the feed is published on, which
   tells this feed from others sharing the encoding */
static bool
nsmequities_totalview_heur_endpoint(packet_info *pinfo)
{
    return nsmequities_totalview_endpoint_of(pinfo) != NULL;
}

/* The frame must hold a complete header */
static bool
nsmequities_totalview_client_packet_heur_header(tvbuff_t *tvb)
{
    return tvb_captured_length(tvb) >= NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_HEADER_SIZE;
}

/* The first frame's declared length fits the stream */
static bool
nsmequities_totalview_client_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Fingerprint of Client Packet: would its message dispatch accept the frame? */
static bool
nsmequities_totalview_client_packet_heur_fingerprint_v502026(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t client_packet_type = tvb_get_uint8(tvb, 2);

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET: /* Login Request Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET: /* Unsequenced Data Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request Packet */
        return true;
    }

    return false;
}

/* Fingerprint of Client Packet: would its message dispatch accept the frame? */
static bool
nsmequities_totalview_client_packet_heur_fingerprint_v32(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 1) {
        return false;
    }

    uint32_t client_packet_type = tvb_get_uint8(tvb, 0);

    switch (client_packet_type) {
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET: /* Login Request Packet */
    case NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET: /* Unsequenced Data Packet */
        return true;
    }

    return false;
}

/* Fingerprint of Client Packet: would any framing's message dispatch accept the frame? */
static bool
nsmequities_totalview_client_packet_heur_fingerprint(tvbuff_t *tvb)
{
    return nsmequities_totalview_client_packet_heur_fingerprint_v502026(tvb)
        || nsmequities_totalview_client_packet_heur_fingerprint_v32(tvb);
}

/* Does the frame pass every test of Client Packet? */
static bool
nsmequities_totalview_client_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo _U_)
{
    if (!nsmequities_totalview_client_packet_heur_header(tvb)) {
        return false;
    }

    if (!nsmequities_totalview_client_packet_heur_frame(tvb)) {
        return false;
    }

    if (!nsmequities_totalview_client_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* The frame must hold a complete header */
static bool
nsmequities_totalview_server_packet_heur_header(tvbuff_t *tvb)
{
    return tvb_captured_length(tvb) >= NSMEQUITIES_TOTALVIEW_SERVER_PACKET_HEADER_SIZE;
}

/* The first frame's declared length fits the stream */
static bool
nsmequities_totalview_server_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + NSMEQUITIES_TOTALVIEW_SERVER_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= NSMEQUITIES_TOTALVIEW_SERVER_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Sequenced Data Packet of Server Packet: the application messages it carries */
static bool
nsmequities_totalview_server_packet_heur_fingerprint_v502026_sequenced_data_packet(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 4) {
        return false;
    }

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, 3);

    switch (sequenced_message_type) {
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT: /* System Event Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_DIRECTORY: /* Stock Directory Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_STOCK_TRADING_ACTION: /* Stock Trading Action Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR: /* Reg Sho Short Sale Price Test Restricted Indicator Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION: /* Market Participant Position Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_DECLINE_LEVEL: /* Mwcb Decline Level Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MWCB_STATUS_LEVEL: /* Mwcb Status Level Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_IPO_QUOTING_PERIOD_UPDATE: /* Ipo Quoting Period Update */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_LULD_AUCTION_COLLAR: /* Luld Auction Collar Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_OPERATIONAL_HALT: /* Operational Halt Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION: /* Add Order No Mpid Attribution Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION: /* Add Order With Mpid Attribution Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED: /* Order Executed Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE: /* Order Executed With Price Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_CANCEL: /* Order Cancel Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_DELETE: /* Order Delete Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACE: /* Order Replace Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NON_CROSS_TRADE: /* Non Cross Trade Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_CROSS_TRADE: /* Cross Trade Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE: /* Broken Trade Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR: /* Net Order Imbalance Indicator Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR: /* Retail Price Improvement Indicator Message */
    case NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DIRECT_LISTING_WITH_CAPITAL_RAISE_PRICE_DISCOVERY: /* Direct Listing With Capital Raise Price Discovery Message */
        return true;
    }

    return false;
}

/* Fingerprint of Server Packet: would its message dispatch accept the frame? */
static bool
nsmequities_totalview_server_packet_heur_fingerprint_v502026(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t server_packet_type = tvb_get_uint8(tvb, 2);

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET: /* Login Accepted Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET: /* Login Rejected Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session Packet */
        return true;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET: /* Sequenced Data Packet */
        return nsmequities_totalview_server_packet_heur_fingerprint_v502026_sequenced_data_packet(tvb);
    }

    return false;
}

/* Sequenced Data Packet of Server Packet: the application messages it carries */
static bool
nsmequities_totalview_server_packet_heur_fingerprint_v32_sequenced_data_packet(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 2) {
        return false;
    }

    uint32_t message_type = tvb_get_uint8(tvb, 1);

    switch (message_type) {
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TIMESTAMP: /* Seconds Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MILLISECONDS: /* Milliseconds Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_SYSTEM_EVENT: /* System Event Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_DIRECTORY: /* Stock Directory Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_STOCK_TRADING_ACTION: /* Stock Trading Action Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_REG_SHO_SHORT_SALE_PRICE_TEST_RESTRICTED_INDICATOR: /* Reg Sho Short Sale Price Test Restricted Indicator Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MARKET_PARTICIPANT_POSITION: /* Market Participant Position Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_NO_MPID_ATTRIBUTION: /* Add Order Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ADD_ORDER_WITH_MPID_ATTRIBUTION: /* Add Order With Mpid Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED: /* Order Executed Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_EXECUTED_WITH_PRICE: /* Order Executed With Price Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_CANCEL: /* Order Cancel Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_DELETE: /* Order Delete Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_ORDER_REPLACE: /* Order Replace Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NON_CROSS_TRADE: /* Trade Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_CROSS_TRADE: /* Cross Trade Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_BROKEN_TRADE: /* Broken Trade Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NET_ORDER_IMBALANCE_INDICATOR: /* Net Order Imbalance Indicator Message */
    case NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_RETAIL_PRICE_IMPROVEMENT_INDICATOR: /* Retail Price Improvement Indicator Message */
        return true;
    }

    return false;
}

/* Fingerprint of Server Packet: would its message dispatch accept the frame? */
static bool
nsmequities_totalview_server_packet_heur_fingerprint_v32(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 1) {
        return false;
    }

    uint32_t server_packet_type = tvb_get_uint8(tvb, 0);

    switch (server_packet_type) {
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET: /* Login Accepted Packet */
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET: /* Login Rejected Packet */
        return true;
    case NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET: /* Sequenced Data Packet */
        return nsmequities_totalview_server_packet_heur_fingerprint_v32_sequenced_data_packet(tvb);
    }

    return false;
}

/* Fingerprint of Server Packet: would any framing's message dispatch accept the frame? */
static bool
nsmequities_totalview_server_packet_heur_fingerprint(tvbuff_t *tvb)
{
    return nsmequities_totalview_server_packet_heur_fingerprint_v502026(tvb)
        || nsmequities_totalview_server_packet_heur_fingerprint_v32(tvb);
}

/* Does the frame pass every test of Server Packet? */
static bool
nsmequities_totalview_server_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo _U_)
{
    if (!nsmequities_totalview_server_packet_heur_header(tvb)) {
        return false;
    }

    if (!nsmequities_totalview_server_packet_heur_frame(tvb)) {
        return false;
    }

    if (!nsmequities_totalview_server_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* The frame must hold a complete header */
static bool
nsmequities_totalview_packet_heur_header(tvbuff_t *tvb)
{
    return tvb_captured_length(tvb) >= NSMEQUITIES_TOTALVIEW_PACKET_HEADER_SIZE;
}

/* Does the frame pass every test of Packet? */
static bool
nsmequities_totalview_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!nsmequities_totalview_heur_endpoint(pinfo)) {
        return false;
    }

    if (!nsmequities_totalview_packet_heur_header(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by content, by the side of the sender's
   connection role, the other side may have sent the conversation's first frame */
static bool
dissect_nsmequities_totalview_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < NSMEQUITIES_TOTALVIEW_MINIMUM_SIZE) {
        return false;
    }

    bool (*first)(tvbuff_t *, packet_info *) = nsmequities_totalview_client_packet_heur_accepts;
    bool (*second)(tvbuff_t *, packet_info *) = nsmequities_totalview_server_packet_heur_accepts;

    if (nsmequities_totalview_role(pinfo) == NSMEQUITIES_TOTALVIEW_ROLE_ACCEPTOR) {
        first = second;
        second = nsmequities_totalview_client_packet_heur_accepts;
    }

    if (first(tvb, pinfo)) {
        dissect_nsmequities_totalview(tvb, pinfo, tree, data);
        return true;
    }

    nsmequities_totalview_swap(pinfo);

    if (second(tvb, pinfo)) {
        dissect_nsmequities_totalview(tvb, pinfo, tree, data);
        return true;
    }

    nsmequities_totalview_swap(pinfo);

    return false;
}

/* Recognize the protocol by the published endpoint it was sent to */
static bool
dissect_nsmequities_totalview_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < NSMEQUITIES_TOTALVIEW_MINIMUM_SIZE) {
        return false;
    }

    if (!nsmequities_totalview_packet_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_nsmequities_totalview(tvb, pinfo, tree, data);

    return true;
}

/*
 * NsmEquities TotalView Registration
 */

void
proto_register_nsmequities_totalview(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_nsmequities_totalview_accepted_sequence_number,
            { NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_accepted_sequence_number_v502023,
            { NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_NAME,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_FILTER,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_TYPE,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_MASK,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SEQUENCE_NUMBER_V502023_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_accepted_session,
            { NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_NAME,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_FILTER,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_TYPE,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_MASK,
              NSMEQUITIES_TOTALVIEW_ACCEPTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_attribution,
            { NSMEQUITIES_TOTALVIEW_ATTRIBUTION_NAME,
              NSMEQUITIES_TOTALVIEW_ATTRIBUTION_FILTER,
              NSMEQUITIES_TOTALVIEW_ATTRIBUTION_TYPE,
              NSMEQUITIES_TOTALVIEW_ATTRIBUTION_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ATTRIBUTION_MASK,
              NSMEQUITIES_TOTALVIEW_ATTRIBUTION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_auction_collar_extension,
            { NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_NAME,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_FILTER,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_TYPE,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_MASK,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_EXTENSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_auction_collar_reference_price,
            { NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_AUCTION_COLLAR_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_authenticity,
            { NSMEQUITIES_TOTALVIEW_AUTHENTICITY_NAME,
              NSMEQUITIES_TOTALVIEW_AUTHENTICITY_FILTER,
              NSMEQUITIES_TOTALVIEW_AUTHENTICITY_TYPE,
              NSMEQUITIES_TOTALVIEW_AUTHENTICITY_DISPLAY,
              VALS(nsmequities_totalview_authenticity_vals),
              NSMEQUITIES_TOTALVIEW_AUTHENTICITY_MASK,
              NSMEQUITIES_TOTALVIEW_AUTHENTICITY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_breached_level,
            { NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_NAME,
              NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_FILTER,
              NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_TYPE,
              NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_DISPLAY,
              VALS(nsmequities_totalview_breached_level_vals),
              NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_MASK,
              NSMEQUITIES_TOTALVIEW_BREACHED_LEVEL_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_buy_sell_indicator,
            { NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_NAME,
              NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_FILTER,
              NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_TYPE,
              NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_DISPLAY,
              VALS(nsmequities_totalview_buy_sell_indicator_vals),
              NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_MASK,
              NSMEQUITIES_TOTALVIEW_BUY_SELL_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_canceled_shares,
            { NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_canceled_shares_v32,
            { NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_NAME,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_MASK,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_canceled_shares_v10,
            { NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_NAME,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_MASK,
              NSMEQUITIES_TOTALVIEW_CANCELED_SHARES_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_client_packet_type,
            { NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DISPLAY,
              VALS(nsmequities_totalview_client_packet_type_vals),
              NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_CLIENT_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_contra_broker_code,
            { NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_CONTRA_BROKER_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_count,
            { NSMEQUITIES_TOTALVIEW_COUNT_NAME,
              NSMEQUITIES_TOTALVIEW_COUNT_FILTER,
              NSMEQUITIES_TOTALVIEW_COUNT_TYPE,
              NSMEQUITIES_TOTALVIEW_COUNT_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_COUNT_MASK,
              NSMEQUITIES_TOTALVIEW_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_cross_price,
            { NSMEQUITIES_TOTALVIEW_CROSS_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_cross_price_v32,
            { NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_CROSS_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_cross_shares,
            { NSMEQUITIES_TOTALVIEW_CROSS_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_CROSS_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_CROSS_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_CROSS_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_CROSS_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_CROSS_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_cross_type,
            { NSMEQUITIES_TOTALVIEW_CROSS_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_CROSS_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_CROSS_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_CROSS_TYPE_DISPLAY,
              VALS(nsmequities_totalview_cross_type_vals),
              NSMEQUITIES_TOTALVIEW_CROSS_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_CROSS_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_current_reference_price,
            { NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_current_reference_price_v32,
            { NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_CURRENT_REFERENCE_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_debug_text,
            { NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_NAME,
              NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_FILTER,
              NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_TYPE,
              NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_MASK,
              NSMEQUITIES_TOTALVIEW_DEBUG_TEXT_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_display,
            { NSMEQUITIES_TOTALVIEW_DISPLAY_NAME,
              NSMEQUITIES_TOTALVIEW_DISPLAY_FILTER,
              NSMEQUITIES_TOTALVIEW_DISPLAY_TYPE,
              NSMEQUITIES_TOTALVIEW_DISPLAY_DISPLAY,
              VALS(nsmequities_totalview_display_vals),
              NSMEQUITIES_TOTALVIEW_DISPLAY_MASK,
              NSMEQUITIES_TOTALVIEW_DISPLAY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_etp_flag,
            { NSMEQUITIES_TOTALVIEW_ETP_FLAG_NAME,
              NSMEQUITIES_TOTALVIEW_ETP_FLAG_FILTER,
              NSMEQUITIES_TOTALVIEW_ETP_FLAG_TYPE,
              NSMEQUITIES_TOTALVIEW_ETP_FLAG_DISPLAY,
              VALS(nsmequities_totalview_etp_flag_vals),
              NSMEQUITIES_TOTALVIEW_ETP_FLAG_MASK,
              NSMEQUITIES_TOTALVIEW_ETP_FLAG_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_etp_leverage_factor,
            { NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_NAME,
              NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_FILTER,
              NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_TYPE,
              NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_MASK,
              NSMEQUITIES_TOTALVIEW_ETP_LEVERAGE_FACTOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_event_code,
            { NSMEQUITIES_TOTALVIEW_EVENT_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_EVENT_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_EVENT_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_EVENT_CODE_DISPLAY,
              VALS(nsmequities_totalview_event_code_vals),
              NSMEQUITIES_TOTALVIEW_EVENT_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_EVENT_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_executed_shares,
            { NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_executed_shares_v32,
            { NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_NAME,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_MASK,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_executed_shares_v10,
            { NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_NAME,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_MASK,
              NSMEQUITIES_TOTALVIEW_EXECUTED_SHARES_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_execution_price,
            { NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_execution_price_v32,
            { NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_EXECUTION_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_far_price,
            { NSMEQUITIES_TOTALVIEW_FAR_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_far_price_v32,
            { NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_FAR_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_financial_status_indicator,
            { NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_NAME,
              NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_FILTER,
              NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_TYPE,
              NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_DISPLAY,
              VALS(nsmequities_totalview_financial_status_indicator_vals),
              NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_MASK,
              NSMEQUITIES_TOTALVIEW_FINANCIAL_STATUS_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_imbalance_direction,
            { NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_NAME,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_FILTER,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_TYPE,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_DISPLAY,
              VALS(nsmequities_totalview_imbalance_direction_vals),
              NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_MASK,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_DIRECTION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_imbalance_shares,
            { NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_imbalance_shares_v32,
            { NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_NAME,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_MASK,
              NSMEQUITIES_TOTALVIEW_IMBALANCE_SHARES_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_interest_flag,
            { NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_NAME,
              NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_FILTER,
              NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_TYPE,
              NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_DISPLAY,
              VALS(nsmequities_totalview_interest_flag_vals),
              NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_MASK,
              NSMEQUITIES_TOTALVIEW_INTEREST_FLAG_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_inverse_indicator,
            { NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_NAME,
              NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_FILTER,
              NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_TYPE,
              NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_DISPLAY,
              VALS(nsmequities_totalview_inverse_indicator_vals),
              NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_MASK,
              NSMEQUITIES_TOTALVIEW_INVERSE_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_ipo_flag,
            { NSMEQUITIES_TOTALVIEW_IPO_FLAG_NAME,
              NSMEQUITIES_TOTALVIEW_IPO_FLAG_FILTER,
              NSMEQUITIES_TOTALVIEW_IPO_FLAG_TYPE,
              NSMEQUITIES_TOTALVIEW_IPO_FLAG_DISPLAY,
              VALS(nsmequities_totalview_ipo_flag_vals),
              NSMEQUITIES_TOTALVIEW_IPO_FLAG_MASK,
              NSMEQUITIES_TOTALVIEW_IPO_FLAG_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_ipo_price,
            { NSMEQUITIES_TOTALVIEW_IPO_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_IPO_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_IPO_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_IPO_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_IPO_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_IPO_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_ipo_quotation_release_qualifier,
            { NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_NAME,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_FILTER,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_TYPE,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_DISPLAY,
              VALS(nsmequities_totalview_ipo_quotation_release_qualifier_vals),
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_MASK,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_QUALIFIER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_ipo_quotation_release_time,
            { NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_NAME,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_FILTER,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_TYPE,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_MASK,
              NSMEQUITIES_TOTALVIEW_IPO_QUOTATION_RELEASE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_issue_classification,
            { NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_NAME,
              NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_FILTER,
              NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_TYPE,
              NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_DISPLAY,
              VALS(nsmequities_totalview_issue_classification_vals),
              NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_MASK,
              NSMEQUITIES_TOTALVIEW_ISSUE_CLASSIFICATION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_issue_sub_type,
            { NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_ISSUE_SUB_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_length,
            { NSMEQUITIES_TOTALVIEW_LENGTH_NAME,
              NSMEQUITIES_TOTALVIEW_LENGTH_FILTER,
              NSMEQUITIES_TOTALVIEW_LENGTH_TYPE,
              NSMEQUITIES_TOTALVIEW_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_LENGTH_MASK,
              NSMEQUITIES_TOTALVIEW_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_level_1,
            { NSMEQUITIES_TOTALVIEW_LEVEL_1_NAME,
              NSMEQUITIES_TOTALVIEW_LEVEL_1_FILTER,
              NSMEQUITIES_TOTALVIEW_LEVEL_1_TYPE,
              NSMEQUITIES_TOTALVIEW_LEVEL_1_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_8_64),
              NSMEQUITIES_TOTALVIEW_LEVEL_1_MASK,
              NSMEQUITIES_TOTALVIEW_LEVEL_1_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_level_2,
            { NSMEQUITIES_TOTALVIEW_LEVEL_2_NAME,
              NSMEQUITIES_TOTALVIEW_LEVEL_2_FILTER,
              NSMEQUITIES_TOTALVIEW_LEVEL_2_TYPE,
              NSMEQUITIES_TOTALVIEW_LEVEL_2_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_8_64),
              NSMEQUITIES_TOTALVIEW_LEVEL_2_MASK,
              NSMEQUITIES_TOTALVIEW_LEVEL_2_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_level_3,
            { NSMEQUITIES_TOTALVIEW_LEVEL_3_NAME,
              NSMEQUITIES_TOTALVIEW_LEVEL_3_FILTER,
              NSMEQUITIES_TOTALVIEW_LEVEL_3_TYPE,
              NSMEQUITIES_TOTALVIEW_LEVEL_3_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_8_64),
              NSMEQUITIES_TOTALVIEW_LEVEL_3_MASK,
              NSMEQUITIES_TOTALVIEW_LEVEL_3_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_locate_code,
            { NSMEQUITIES_TOTALVIEW_LOCATE_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_LOCATE_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_LOCATE_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_LOCATE_CODE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_LOCATE_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_LOCATE_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_lower_auction_collar_price,
            { NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_LOWER_AUCTION_COLLAR_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_lower_price_range_collar,
            { NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_NAME,
              NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_FILTER,
              NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_TYPE,
              NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_MASK,
              NSMEQUITIES_TOTALVIEW_LOWER_PRICE_RANGE_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_luld_reference_price_tier,
            { NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_NAME,
              NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_FILTER,
              NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_TYPE,
              NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_DISPLAY,
              VALS(nsmequities_totalview_luld_reference_price_tier_vals),
              NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_MASK,
              NSMEQUITIES_TOTALVIEW_LULD_REFERENCE_PRICE_TIER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_market_category,
            { NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_NAME,
              NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_FILTER,
              NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_TYPE,
              NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_DISPLAY,
              VALS(nsmequities_totalview_market_category_vals),
              NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_MASK,
              NSMEQUITIES_TOTALVIEW_MARKET_CATEGORY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_market_code,
            { NSMEQUITIES_TOTALVIEW_MARKET_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_MARKET_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_MARKET_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_MARKET_CODE_DISPLAY,
              VALS(nsmequities_totalview_market_code_vals),
              NSMEQUITIES_TOTALVIEW_MARKET_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_MARKET_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_market_maker_mode,
            { NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_NAME,
              NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_FILTER,
              NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_TYPE,
              NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_DISPLAY,
              VALS(nsmequities_totalview_market_maker_mode_vals),
              NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_MASK,
              NSMEQUITIES_TOTALVIEW_MARKET_MAKER_MODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_market_participant_state,
            { NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_NAME,
              NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_FILTER,
              NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_TYPE,
              NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_DISPLAY,
              VALS(nsmequities_totalview_market_participant_state_vals),
              NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_MASK,
              NSMEQUITIES_TOTALVIEW_MARKET_PARTICIPANT_STATE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_match_number,
            { NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_match_number_v32,
            { NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_NAME,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_MASK,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_match_number_v30,
            { NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_NAME,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_FILTER,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_TYPE,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_MASK,
              NSMEQUITIES_TOTALVIEW_MATCH_NUMBER_V30_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_maximum_allowable_price,
            { NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_MAXIMUM_ALLOWABLE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_message_count,
            { NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_NAME,
              NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_FILTER,
              NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_TYPE,
              NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_MASK,
              NSMEQUITIES_TOTALVIEW_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_message_length,
            { NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_NAME,
              NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_FILTER,
              NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_TYPE,
              NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_MASK,
              NSMEQUITIES_TOTALVIEW_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_message_type,
            { NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DISPLAY,
              VALS(nsmequities_totalview_message_type_vals),
              NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_millisecond,
            { NSMEQUITIES_TOTALVIEW_MILLISECOND_NAME,
              NSMEQUITIES_TOTALVIEW_MILLISECOND_FILTER,
              NSMEQUITIES_TOTALVIEW_MILLISECOND_TYPE,
              NSMEQUITIES_TOTALVIEW_MILLISECOND_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MILLISECOND_MASK,
              NSMEQUITIES_TOTALVIEW_MILLISECOND_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_minimum_allowable_price,
            { NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_MINIMUM_ALLOWABLE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_mmid,
            { NSMEQUITIES_TOTALVIEW_MMID_NAME,
              NSMEQUITIES_TOTALVIEW_MMID_FILTER,
              NSMEQUITIES_TOTALVIEW_MMID_TYPE,
              NSMEQUITIES_TOTALVIEW_MMID_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MMID_MASK,
              NSMEQUITIES_TOTALVIEW_MMID_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_mpid,
            { NSMEQUITIES_TOTALVIEW_MPID_NAME,
              NSMEQUITIES_TOTALVIEW_MPID_FILTER,
              NSMEQUITIES_TOTALVIEW_MPID_TYPE,
              NSMEQUITIES_TOTALVIEW_MPID_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_MPID_MASK,
              NSMEQUITIES_TOTALVIEW_MPID_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_nanoseconds,
            { NSMEQUITIES_TOTALVIEW_NANOSECONDS_NAME,
              NSMEQUITIES_TOTALVIEW_NANOSECONDS_FILTER,
              NSMEQUITIES_TOTALVIEW_NANOSECONDS_TYPE,
              NSMEQUITIES_TOTALVIEW_NANOSECONDS_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_NANOSECONDS_MASK,
              NSMEQUITIES_TOTALVIEW_NANOSECONDS_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_near_execution_price,
            { NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_near_execution_time,
            { NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_NAME,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_FILTER,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_TYPE,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_MASK,
              NSMEQUITIES_TOTALVIEW_NEAR_EXECUTION_TIME_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_near_price,
            { NSMEQUITIES_TOTALVIEW_NEAR_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_near_price_v32,
            { NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_NEAR_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_new_order_reference_number,
            { NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_new_order_reference_number_v32,
            { NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_NAME,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_MASK,
              NSMEQUITIES_TOTALVIEW_NEW_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_open_eligibility_status,
            { NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_NAME,
              NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_FILTER,
              NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_TYPE,
              NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_DISPLAY,
              VALS(nsmequities_totalview_open_eligibility_status_vals),
              NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_MASK,
              NSMEQUITIES_TOTALVIEW_OPEN_ELIGIBILITY_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_operational_halt_action,
            { NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_NAME,
              NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_FILTER,
              NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_TYPE,
              NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_DISPLAY,
              VALS(nsmequities_totalview_operational_halt_action_vals),
              NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_MASK,
              NSMEQUITIES_TOTALVIEW_OPERATIONAL_HALT_ACTION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_order_reference_number,
            { NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_order_reference_number_v32,
            { NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_NAME,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_MASK,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_order_reference_number_v30,
            { NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_NAME,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_FILTER,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_TYPE,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_MASK,
              NSMEQUITIES_TOTALVIEW_ORDER_REFERENCE_NUMBER_V30_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_original_order_reference_number,
            { NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_original_order_reference_number_v32,
            { NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_NAME,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_MASK,
              NSMEQUITIES_TOTALVIEW_ORIGINAL_ORDER_REFERENCE_NUMBER_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_packet_length,
            { NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_NAME,
              NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_FILTER,
              NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_TYPE,
              NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_MASK,
              NSMEQUITIES_TOTALVIEW_PACKET_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_paired_shares,
            { NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_paired_shares_v32,
            { NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_NAME,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_MASK,
              NSMEQUITIES_TOTALVIEW_PAIRED_SHARES_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_password,
            { NSMEQUITIES_TOTALVIEW_PASSWORD_NAME,
              NSMEQUITIES_TOTALVIEW_PASSWORD_FILTER,
              NSMEQUITIES_TOTALVIEW_PASSWORD_TYPE,
              NSMEQUITIES_TOTALVIEW_PASSWORD_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PASSWORD_MASK,
              NSMEQUITIES_TOTALVIEW_PASSWORD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_password_v32,
            { NSMEQUITIES_TOTALVIEW_PASSWORD_V32_NAME,
              NSMEQUITIES_TOTALVIEW_PASSWORD_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_PASSWORD_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_PASSWORD_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PASSWORD_V32_MASK,
              NSMEQUITIES_TOTALVIEW_PASSWORD_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_price,
            { NSMEQUITIES_TOTALVIEW_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_price_v32,
            { NSMEQUITIES_TOTALVIEW_PRICE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_PRICE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_PRICE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_PRICE_V32_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_PRICE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_PRICE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_price_v10,
            { NSMEQUITIES_TOTALVIEW_PRICE_V10_NAME,
              NSMEQUITIES_TOTALVIEW_PRICE_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_PRICE_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_PRICE_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_PRICE_V10_MASK,
              NSMEQUITIES_TOTALVIEW_PRICE_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_price_variation_indicator,
            { NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_NAME,
              NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_FILTER,
              NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_TYPE,
              NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_DISPLAY,
              VALS(nsmequities_totalview_price_variation_indicator_vals),
              NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_MASK,
              NSMEQUITIES_TOTALVIEW_PRICE_VARIATION_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_primary_market_maker,
            { NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_NAME,
              NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_FILTER,
              NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_TYPE,
              NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_DISPLAY,
              VALS(nsmequities_totalview_primary_market_maker_vals),
              NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_MASK,
              NSMEQUITIES_TOTALVIEW_PRIMARY_MARKET_MAKER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_printable,
            { NSMEQUITIES_TOTALVIEW_PRINTABLE_NAME,
              NSMEQUITIES_TOTALVIEW_PRINTABLE_FILTER,
              NSMEQUITIES_TOTALVIEW_PRINTABLE_TYPE,
              NSMEQUITIES_TOTALVIEW_PRINTABLE_DISPLAY,
              VALS(nsmequities_totalview_printable_vals),
              NSMEQUITIES_TOTALVIEW_PRINTABLE_MASK,
              NSMEQUITIES_TOTALVIEW_PRINTABLE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_reason,
            { NSMEQUITIES_TOTALVIEW_REASON_NAME,
              NSMEQUITIES_TOTALVIEW_REASON_FILTER,
              NSMEQUITIES_TOTALVIEW_REASON_TYPE,
              NSMEQUITIES_TOTALVIEW_REASON_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REASON_MASK,
              NSMEQUITIES_TOTALVIEW_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_reason_code,
            { NSMEQUITIES_TOTALVIEW_REASON_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_REASON_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_REASON_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_REASON_CODE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REASON_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_reg_sho_action,
            { NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_NAME,
              NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_FILTER,
              NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_TYPE,
              NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_DISPLAY,
              VALS(nsmequities_totalview_reg_sho_action_vals),
              NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_MASK,
              NSMEQUITIES_TOTALVIEW_REG_SHO_ACTION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_reject_reason_code,
            { NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_NAME,
              NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_FILTER,
              NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_TYPE,
              NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_DISPLAY,
              VALS(nsmequities_totalview_reject_reason_code_vals),
              NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_MASK,
              NSMEQUITIES_TOTALVIEW_REJECT_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_sequence_number,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_sequence_number_v502023,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V502023_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_sequence_number_v32,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_sequence_number_v30,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SEQUENCE_NUMBER_V30_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_session,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_requested_session_v32,
            { NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_NAME,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_MASK,
              NSMEQUITIES_TOTALVIEW_REQUESTED_SESSION_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_reserved,
            { NSMEQUITIES_TOTALVIEW_RESERVED_NAME,
              NSMEQUITIES_TOTALVIEW_RESERVED_FILTER,
              NSMEQUITIES_TOTALVIEW_RESERVED_TYPE,
              NSMEQUITIES_TOTALVIEW_RESERVED_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_RESERVED_MASK,
              NSMEQUITIES_TOTALVIEW_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_round_lot_size,
            { NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_NAME,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_FILTER,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_TYPE,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_MASK,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_round_lot_size_v32,
            { NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_NAME,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_MASK,
              NSMEQUITIES_TOTALVIEW_ROUND_LOT_SIZE_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_round_lots_only,
            { NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_NAME,
              NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_FILTER,
              NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_TYPE,
              NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_DISPLAY,
              VALS(nsmequities_totalview_round_lots_only_vals),
              NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_MASK,
              NSMEQUITIES_TOTALVIEW_ROUND_LOTS_ONLY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_second,
            { NSMEQUITIES_TOTALVIEW_SECOND_NAME,
              NSMEQUITIES_TOTALVIEW_SECOND_FILTER,
              NSMEQUITIES_TOTALVIEW_SECOND_TYPE,
              NSMEQUITIES_TOTALVIEW_SECOND_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SECOND_MASK,
              NSMEQUITIES_TOTALVIEW_SECOND_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_second_v32,
            { NSMEQUITIES_TOTALVIEW_SECOND_V32_NAME,
              NSMEQUITIES_TOTALVIEW_SECOND_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_SECOND_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_SECOND_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SECOND_V32_MASK,
              NSMEQUITIES_TOTALVIEW_SECOND_V32_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_sequence,
            { NSMEQUITIES_TOTALVIEW_SEQUENCE_NAME,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_FILTER,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_TYPE,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_MASK,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_sequence_number,
            { NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_sequence_number_v30,
            { NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_NAME,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_FILTER,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_TYPE,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_MASK,
              NSMEQUITIES_TOTALVIEW_SEQUENCE_NUMBER_V30_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_sequenced_message_type,
            { NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DISPLAY,
              VALS(nsmequities_totalview_sequenced_message_type_vals),
              NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_SEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_server_packet_type,
            { NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DISPLAY,
              VALS(nsmequities_totalview_server_packet_type_vals),
              NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_SERVER_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_session,
            { NSMEQUITIES_TOTALVIEW_SESSION_NAME,
              NSMEQUITIES_TOTALVIEW_SESSION_FILTER,
              NSMEQUITIES_TOTALVIEW_SESSION_TYPE,
              NSMEQUITIES_TOTALVIEW_SESSION_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SESSION_MASK,
              NSMEQUITIES_TOTALVIEW_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_session_v30,
            { NSMEQUITIES_TOTALVIEW_SESSION_V30_NAME,
              NSMEQUITIES_TOTALVIEW_SESSION_V30_FILTER,
              NSMEQUITIES_TOTALVIEW_SESSION_V30_TYPE,
              NSMEQUITIES_TOTALVIEW_SESSION_V30_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SESSION_V30_MASK,
              NSMEQUITIES_TOTALVIEW_SESSION_V30_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_session_v10,
            { NSMEQUITIES_TOTALVIEW_SESSION_V10_NAME,
              NSMEQUITIES_TOTALVIEW_SESSION_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_SESSION_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_SESSION_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SESSION_V10_MASK,
              NSMEQUITIES_TOTALVIEW_SESSION_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_shares,
            { NSMEQUITIES_TOTALVIEW_SHARES_NAME,
              NSMEQUITIES_TOTALVIEW_SHARES_FILTER,
              NSMEQUITIES_TOTALVIEW_SHARES_TYPE,
              NSMEQUITIES_TOTALVIEW_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SHARES_MASK,
              NSMEQUITIES_TOTALVIEW_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_shares_v20a,
            { NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_NAME,
              NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_FILTER,
              NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_TYPE,
              NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_MASK,
              NSMEQUITIES_TOTALVIEW_SHARES_V2_0A_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_shares_v10,
            { NSMEQUITIES_TOTALVIEW_SHARES_V10_NAME,
              NSMEQUITIES_TOTALVIEW_SHARES_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_SHARES_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_SHARES_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SHARES_V10_MASK,
              NSMEQUITIES_TOTALVIEW_SHARES_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_shares_numeric_6,
            { NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_NAME,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_FILTER,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_TYPE,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_MASK,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_6_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_shares_numeric_9,
            { NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_NAME,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_FILTER,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_TYPE,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_MASK,
              NSMEQUITIES_TOTALVIEW_SHARES_NUMERIC_9_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_short_sale_threshold_indicator,
            { NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_NAME,
              NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_FILTER,
              NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_TYPE,
              NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_DISPLAY,
              VALS(nsmequities_totalview_short_sale_threshold_indicator_vals),
              NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_MASK,
              NSMEQUITIES_TOTALVIEW_SHORT_SALE_THRESHOLD_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_side,
            { NSMEQUITIES_TOTALVIEW_SIDE_NAME,
              NSMEQUITIES_TOTALVIEW_SIDE_FILTER,
              NSMEQUITIES_TOTALVIEW_SIDE_TYPE,
              NSMEQUITIES_TOTALVIEW_SIDE_DISPLAY,
              VALS(nsmequities_totalview_side_vals),
              NSMEQUITIES_TOTALVIEW_SIDE_MASK,
              NSMEQUITIES_TOTALVIEW_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock,
            { NSMEQUITIES_TOTALVIEW_STOCK_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_v40,
            { NSMEQUITIES_TOTALVIEW_STOCK_V40_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_V40_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_V40_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_V40_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_V40_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_V40_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_alpha_6,
            { NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_6_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_alpha_8,
            { NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHA_8_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_alphabetic_6,
            { NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHABETIC_6_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_alphanumeric_6,
            { NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_6_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_alphanumeric_8,
            { NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_ALPHANUMERIC_8_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_halted,
            { NSMEQUITIES_TOTALVIEW_STOCK_HALTED_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_HALTED_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_HALTED_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_HALTED_DISPLAY,
              VALS(nsmequities_totalview_stock_halted_vals),
              NSMEQUITIES_TOTALVIEW_STOCK_HALTED_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_HALTED_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_stock_locate,
            { NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_NAME,
              NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_FILTER,
              NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_TYPE,
              NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_MASK,
              NSMEQUITIES_TOTALVIEW_STOCK_LOCATE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_text,
            { NSMEQUITIES_TOTALVIEW_TEXT_NAME,
              NSMEQUITIES_TOTALVIEW_TEXT_FILTER,
              NSMEQUITIES_TOTALVIEW_TEXT_TYPE,
              NSMEQUITIES_TOTALVIEW_TEXT_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_TEXT_MASK,
              NSMEQUITIES_TOTALVIEW_TEXT_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_timestamp,
            { NSMEQUITIES_TOTALVIEW_TIMESTAMP_NAME,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_FILTER,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_TYPE,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_MASK,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_timestamp_v20a,
            { NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_NAME,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_FILTER,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_TYPE,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_MASK,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V2_0A_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_timestamp_v10,
            { NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_NAME,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_FILTER,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_TYPE,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_MASK,
              NSMEQUITIES_TOTALVIEW_TIMESTAMP_V10_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_tracking_number,
            { NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_NAME,
              NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_FILTER,
              NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_TYPE,
              NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_MASK,
              NSMEQUITIES_TOTALVIEW_TRACKING_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_trading_state,
            { NSMEQUITIES_TOTALVIEW_TRADING_STATE_NAME,
              NSMEQUITIES_TOTALVIEW_TRADING_STATE_FILTER,
              NSMEQUITIES_TOTALVIEW_TRADING_STATE_TYPE,
              NSMEQUITIES_TOTALVIEW_TRADING_STATE_DISPLAY,
              VALS(nsmequities_totalview_trading_state_vals),
              NSMEQUITIES_TOTALVIEW_TRADING_STATE_MASK,
              NSMEQUITIES_TOTALVIEW_TRADING_STATE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_unsequenced_message,
            { NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_NAME,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_FILTER,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_MASK,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_unsequenced_message_type,
            { NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_NAME,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_FILTER,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_TYPE,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_MASK,
              NSMEQUITIES_TOTALVIEW_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_upper_auction_collar_price,
            { NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_NAME,
              NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_FILTER,
              NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_TYPE,
              NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_MASK,
              NSMEQUITIES_TOTALVIEW_UPPER_AUCTION_COLLAR_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_upper_price_range_collar,
            { NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_NAME,
              NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_FILTER,
              NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_TYPE,
              NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_DISPLAY,
              CF_FUNC(nsmequities_totalview_format_decimal_4_32),
              NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_MASK,
              NSMEQUITIES_TOTALVIEW_UPPER_PRICE_RANGE_COLLAR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_username,
            { NSMEQUITIES_TOTALVIEW_USERNAME_NAME,
              NSMEQUITIES_TOTALVIEW_USERNAME_FILTER,
              NSMEQUITIES_TOTALVIEW_USERNAME_TYPE,
              NSMEQUITIES_TOTALVIEW_USERNAME_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_USERNAME_MASK,
              NSMEQUITIES_TOTALVIEW_USERNAME_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_totalview_username_v32,
            { NSMEQUITIES_TOTALVIEW_USERNAME_V32_NAME,
              NSMEQUITIES_TOTALVIEW_USERNAME_V32_FILTER,
              NSMEQUITIES_TOTALVIEW_USERNAME_V32_TYPE,
              NSMEQUITIES_TOTALVIEW_USERNAME_V32_DISPLAY,
              NULL,
              NSMEQUITIES_TOTALVIEW_USERNAME_V32_MASK,
              NSMEQUITIES_TOTALVIEW_USERNAME_V32_DESCRIPTION,
              HFILL } },

        /* Generated */
        { &hf_nsmequities_totalview_time_of_day,
            { NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_NAME,
              NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_FILTER,
              FT_RELATIVE_TIME,
              BASE_NONE,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_TIME_OF_DAY_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_utc,
            { NSMEQUITIES_TOTALVIEW_UTC_NAME,
              NSMEQUITIES_TOTALVIEW_UTC_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_UTC,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_UTC_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_local,
            { NSMEQUITIES_TOTALVIEW_LOCAL_NAME,
              NSMEQUITIES_TOTALVIEW_LOCAL_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_LOCAL,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_LOCAL_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_elapsed_hundredths,
            { NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_NAME,
              NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_ELAPSED_HUNDREDTHS_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_elapsed_milliseconds,
            { NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_NAME,
              NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_ELAPSED_MILLISECONDS_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_elapsed_nanoseconds,
            { NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_NAME,
              NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_ELAPSED_NANOSECONDS_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_totalview_elapsed_seconds,
            { NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_NAME,
              NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              NSMEQUITIES_TOTALVIEW_ELAPSED_SECONDS_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_nsmequities_totalview,
        &ett_nsmequities_totalview_header,
        &ett_nsmequities_totalview_message,
        &ett_nsmequities_totalview_timestamp,
        &ett_nsmequities_totalview_client_packet_header,
        &ett_nsmequities_totalview_server_packet_header,
        &ett_nsmequities_totalview_message_header,
        &ett_nsmequities_totalview_sequenced_message_header,
        &ett_nsmequities_totalview_message_header_v30,
        &ett_nsmequities_totalview_sequenced_message_header_v20a,
        &ett_nsmequities_totalview_message_header_v20a,
        &ett_nsmequities_totalview_sequenced_message_header_v10,
    };

    static ei_register_info ei[] = {
        { &ei_nsmequities_totalview_length,
            { NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_FILTER,
              NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_GROUP,
              NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_SEVERITY,
              NSMEQUITIES_TOTALVIEW_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_nsmequities_totalview = proto_register_protocol(NSMEQUITIES_TOTALVIEW_PROTOCOL_NAME, NSMEQUITIES_TOTALVIEW_PROTOCOL_SHORT, NSMEQUITIES_TOTALVIEW_PROTOCOL_FILTER);

    proto_register_field_array(proto_nsmequities_totalview, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_nsmequities_totalview = expert_register_protocol(proto_nsmequities_totalview);
    expert_register_field_array(expert_nsmequities_totalview, ei, array_length(ei));

    module_t *prefs = prefs_register_protocol(proto_nsmequities_totalview, NULL);

    prefs_register_enum_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_VERSION_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_version,
        nsmequities_totalview_version_vals,
        false);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_show_headers);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_show_session_messages);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_show_application_messages);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_SHOW_MESSAGES_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_show_messages);

    prefs_register_uint_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &nsmequities_totalview_pref_decimal_places);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_READ_MILLISECOND_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_read_millisecond);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_READ_NANOSECONDS_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_read_nanoseconds);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_READ_SECOND_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_read_second);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_READ_TIMESTAMP_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_read_timestamp);

    prefs_register_enum_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_ASSUME_ROLE_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_assume_role,
        nsmequities_totalview_assume_role_vals,
        false);

    prefs_register_uint_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION,
        10,
        &nsmequities_totalview_pref_acceptor_port);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_SWAP_SIDES_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_swap_sides);

    prefs_register_bool_preference(
        prefs,
        NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_NAME,
        NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_TITLE,
        NSMEQUITIES_TOTALVIEW_INDEXES_PREFERENCE_DESCRIPTION,
        &nsmequities_totalview_pref_show_indexes);

    nsmequities_totalview_handle = register_dissector(NSMEQUITIES_TOTALVIEW_PROTOCOL_FILTER, dissect_nsmequities_totalview, proto_nsmequities_totalview);
}

void
proto_reg_handoff_nsmequities_totalview(void)
{
    heur_dissector_add("tcp", dissect_nsmequities_totalview_tcp_heur, "Nasdaq TotalView Itch over TCP",
        "nsmequities_totalview_tcp", proto_nsmequities_totalview, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_nsmequities_totalview_udp_heur, "Nasdaq TotalView Itch over UDP",
        "nsmequities_totalview_udp", proto_nsmequities_totalview, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", nsmequities_totalview_handle);
    dissector_add_for_decode_as("udp.port", nsmequities_totalview_handle);
}
