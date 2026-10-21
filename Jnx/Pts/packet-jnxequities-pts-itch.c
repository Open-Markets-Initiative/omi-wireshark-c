/* packet-jnxequities-pts-itch.c
 * Routines for Jnx Pts Itch dissection
 *
 * Aggregated protocol versions: 1.7
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Jnx.JnxEquities.Pts.Itch.v1.7
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

void proto_register_jnxequities_pts_itch(void);
void proto_reg_handoff_jnxequities_pts_itch(void);

static dissector_handle_t jnxequities_pts_itch_handle;

static int proto_jnxequities_pts_itch;

/*
 * JnxEquities Pts Protocol
 */

#define JNXEQUITIES_PTS_ITCH_PROTOCOL_NAME "Jnx Pts Itch"
#define JNXEQUITIES_PTS_ITCH_PROTOCOL_SHORT "JNXEQUITIES.PTS.ITCH"
#define JNXEQUITIES_PTS_ITCH_PROTOCOL_FILTER "jnxequities.pts.itch"

/*
 * JnxEquities Pts Header
 */

#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_HEADER_SIZE 3 /* Client Soup Bin Tcp Packet */
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_HEADER_SIZE 3 /* Server Soup Bin Tcp Packet */
#define JNXEQUITIES_PTS_ITCH_PACKET_HEADER_SIZE 20 /* Packet Header */

/*
 * JnxEquities Pts Field Handles
 */

static int hf_jnxequities_pts_itch_accepted_sequence_number;
static int hf_jnxequities_pts_itch_accepted_session;
static int hf_jnxequities_pts_itch_attribution;
static int hf_jnxequities_pts_itch_buy_sell_indicator;
static int hf_jnxequities_pts_itch_client_packet_type;
static int hf_jnxequities_pts_itch_debug_text;
static int hf_jnxequities_pts_itch_executed_quantity;
static int hf_jnxequities_pts_itch_group;
static int hf_jnxequities_pts_itch_lower_price_limit;
static int hf_jnxequities_pts_itch_match_number;
static int hf_jnxequities_pts_itch_message_count;
static int hf_jnxequities_pts_itch_message_length;
static int hf_jnxequities_pts_itch_message_type;
static int hf_jnxequities_pts_itch_nanoseconds;
static int hf_jnxequities_pts_itch_new_order_number;
static int hf_jnxequities_pts_itch_order_number;
static int hf_jnxequities_pts_itch_order_type;
static int hf_jnxequities_pts_itch_orderbook_code;
static int hf_jnxequities_pts_itch_orderbook_id;
static int hf_jnxequities_pts_itch_original_order_number;
static int hf_jnxequities_pts_itch_packet_length;
static int hf_jnxequities_pts_itch_password;
static int hf_jnxequities_pts_itch_price;
static int hf_jnxequities_pts_itch_price_decimals;
static int hf_jnxequities_pts_itch_price_start;
static int hf_jnxequities_pts_itch_price_tick_size;
static int hf_jnxequities_pts_itch_price_tick_size_table_id;
static int hf_jnxequities_pts_itch_quantity;
static int hf_jnxequities_pts_itch_reject_reason_code;
static int hf_jnxequities_pts_itch_requested_sequence_number;
static int hf_jnxequities_pts_itch_requested_session;
static int hf_jnxequities_pts_itch_round_lot_size;
static int hf_jnxequities_pts_itch_seconds;
static int hf_jnxequities_pts_itch_sequence_number;
static int hf_jnxequities_pts_itch_sequenced_message_type;
static int hf_jnxequities_pts_itch_server_packet_type;
static int hf_jnxequities_pts_itch_session;
static int hf_jnxequities_pts_itch_short_selling_state;
static int hf_jnxequities_pts_itch_system_event;
static int hf_jnxequities_pts_itch_trading_state;
static int hf_jnxequities_pts_itch_unsequenced_message;
static int hf_jnxequities_pts_itch_unsequenced_message_type;
static int hf_jnxequities_pts_itch_upper_price_limit;
static int hf_jnxequities_pts_itch_username;
static int hf_jnxequities_pts_itch_time_of_day;
static int hf_jnxequities_pts_itch_utc;
static int hf_jnxequities_pts_itch_local;
static int hf_jnxequities_pts_itch_elapsed_nanoseconds;
static int hf_jnxequities_pts_itch_elapsed_seconds;

/* The time of day a timestamp reads as, beneath the instant it names */
#define JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_NAME "Time Of Day"
#define JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_FILTER "jnxequities.pts.itch.timeofday"
#define JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_DESCRIPTION "Time of day composed from the second the feed established and the count within it"

/* The instant a time of day names, dated by the frame that carried it */
#define JNXEQUITIES_PTS_ITCH_UTC_NAME "Utc"
#define JNXEQUITIES_PTS_ITCH_UTC_FILTER "jnxequities.pts.itch.utc"
#define JNXEQUITIES_PTS_ITCH_UTC_DESCRIPTION "The instant the time of day names, dated by the frame that carried the message"

/* The same instant as the reader's own clock reads it */
#define JNXEQUITIES_PTS_ITCH_LOCAL_NAME "Local"
#define JNXEQUITIES_PTS_ITCH_LOCAL_FILTER "jnxequities.pts.itch.local"
#define JNXEQUITIES_PTS_ITCH_LOCAL_DESCRIPTION "The instant the time of day names, in the reader's own timezone"

/* The count the wire carries, under the reading of it */
#define JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_NAME "Nanoseconds"
#define JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_FILTER "jnxequities.pts.itch.elapsed.nanoseconds"
#define JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"
#define JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_NAME "Seconds"
#define JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_FILTER "jnxequities.pts.itch.elapsed.seconds"
#define JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"

/*
 * JnxEquities Pts Subtrees
 */

static int ett_jnxequities_pts_itch;
static int ett_jnxequities_pts_itch_header;
static int ett_jnxequities_pts_itch_message;
static int ett_jnxequities_pts_itch_timestamp;
static int ett_jnxequities_pts_itch_client_packet_header;
static int ett_jnxequities_pts_itch_server_packet_header;
static int ett_jnxequities_pts_itch_message_header;

/*
 * JnxEquities Pts Expert Information
 */

/* Message length does not account for the parsed fields */
#define JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_FILTER "jnxequities.pts.itch.length.invalid"
#define JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_GROUP PI_MALFORMED
#define JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_SEVERITY PI_ERROR
#define JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_jnxequities_pts_itch_length;

/*
 * JnxEquities Pts Preferences
 */

#define JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_NAME "version"
#define JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_TITLE "Protocol version"
#define JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define JNXEQUITIES_PTS_ITCH_VERSION_AUTOMATIC 0
#define JNXEQUITIES_PTS_ITCH_VERSION_1_7     1

static const enum_val_t jnxequities_pts_itch_version_vals[] = {
    { "automatic", "Automatic (by send time)", JNXEQUITIES_PTS_ITCH_VERSION_AUTOMATIC },
    { "v1.7", "1.7", JNXEQUITIES_PTS_ITCH_VERSION_1_7 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
jnxequities_pts_itch_version_name(int version)
{
    switch (version) {
    case JNXEQUITIES_PTS_ITCH_VERSION_1_7:
        return "1.7";
    }

    return "";
}

static int jnxequities_pts_itch_pref_version = JNXEQUITIES_PTS_ITCH_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */

/* Show preferences, one per message and struct */
#define JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_NAME "show.sessionmessages"
#define JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE "Show Session Messages"
#define JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION "Show Session Messages in the protocol tree"

#define JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

static bool jnxequities_pts_itch_show_headers = true;
static bool jnxequities_pts_itch_show_session_messages = true;
static bool jnxequities_pts_itch_show_application_messages = true;

/* Decimal places shown, the wire precision by default */
#define JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_NAME "decimal.places"
#define JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned jnxequities_pts_itch_pref_decimal_places = 1;

/* Nanoseconds read as a time of day, which is the default */
#define JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_NAME "read.nanoseconds"
#define JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_TITLE "Read Nanoseconds as a time"
#define JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_DESCRIPTION "Read Nanoseconds as a time of day, with the instant it names beneath it. Off states the nanoseconds since midnight the wire carries and nothing else"

static bool jnxequities_pts_itch_pref_read_nanoseconds = true;

/* Seconds read as a time of day, which is the default */
#define JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_NAME "read.seconds"
#define JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_TITLE "Read Seconds as a time"
#define JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_DESCRIPTION "Read Seconds as a time of day, with the instant it names beneath it. Off states the seconds since midnight the wire carries and nothing else"

static bool jnxequities_pts_itch_pref_read_seconds = true;

/* Connection roles, Client is the initiator, Server is the acceptor */
#define JNXEQUITIES_PTS_ITCH_ROLE_RESOLVE 0
#define JNXEQUITIES_PTS_ITCH_ROLE_INITIATOR 1
#define JNXEQUITIES_PTS_ITCH_ROLE_ACCEPTOR 2

#define JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_NAME "role.assume"
#define JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_TITLE "Assume role"
#define JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_DESCRIPTION "Connection role assumed for every frame, for captures that start mid conversation"
#define JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_NAME "role.acceptorport"
#define JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_TITLE "Acceptor port"
#define JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION "Port the acceptor listens on, 0 resolves each frame's role from its conversation"
#define JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_NAME "role.swapsides"
#define JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_TITLE "Swap sides"
#define JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_DESCRIPTION "The first frame seen of each conversation was the acceptor's, not the initiator's, for captures that start mid conversation"

static int jnxequities_pts_itch_pref_assume_role = JNXEQUITIES_PTS_ITCH_ROLE_RESOLVE;
static unsigned jnxequities_pts_itch_pref_acceptor_port = 0;
static bool jnxequities_pts_itch_pref_swap_sides = false;

static const enum_val_t jnxequities_pts_itch_assume_role_vals[] = {
    { "resolve", "Resolve from the conversation", JNXEQUITIES_PTS_ITCH_ROLE_RESOLVE },
    { "initiator", "Initiator (Client)", JNXEQUITIES_PTS_ITCH_ROLE_INITIATOR },
    { "acceptor", "Acceptor (Server)", JNXEQUITIES_PTS_ITCH_ROLE_ACCEPTOR },
    { NULL, NULL, 0 }
};

/* Entries of a repeating group are numbered */
#define JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_NAME "show.indexes"
#define JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_TITLE "Show Indexes"
#define JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_DESCRIPTION "Number the entries of a repeating group in the protocol tree"

static bool jnxequities_pts_itch_pref_show_indexes = true;

/* Ports the feed arrives on, assigned per deployment */
#define JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_NAME "ports"
#define JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_TITLE "Ports"
#define JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_DEFAULT "11002,15001,15002"
#define JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *jnxequities_pts_itch_pref_ports;

/*
 * JnxEquities Pts Methods
 */

/* Select the protocol version, this protocol has one */
static int
jnxequities_pts_itch_version(uint64_t seconds _U_)
{
    return JNXEQUITIES_PTS_ITCH_VERSION_1_7;
}

/* Label an offset from midnight as the clock reads it */
static void
jnxequities_pts_itch_time_of_day_label(char *buf, size_t size, const nstime_t *time)
{
    uint32_t seconds = (uint32_t)time->secs;

    snprintf(buf, size, "%02u:%02u:%02u.%09u",
        seconds / 3600, (seconds / 60) % 60, seconds % 60, (uint32_t)time->nsecs);
}

/* What this protocol remembers across the frames of a conversation */
typedef struct jnxequities_pts_itch_conversation {
    address initiator;
    uint32_t port;
    bool swapped;
    uint64_t seconds;
} jnxequities_pts_itch_conversation;

/* Record of the frame's conversation, created on its first frame */
static jnxequities_pts_itch_conversation *
jnxequities_pts_itch_conversation_of(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    jnxequities_pts_itch_conversation *state = (jnxequities_pts_itch_conversation *)conversation_get_proto_data(conversation, proto_jnxequities_pts_itch);

    if (state == NULL) {
        state = wmem_new0(wmem_file_scope(), jnxequities_pts_itch_conversation);
        copy_address_wmem(wmem_file_scope(), &state->initiator, &pinfo->src);
        state->port = pinfo->srcport;
        conversation_add_proto_data(conversation, proto_jnxequities_pts_itch, state);
    }

    return state;
}

/* The second the dissection in progress sits in */
static uint64_t jnxequities_pts_itch_anchor;

/* Seed the second from the frame's own record, the frames before it
   established it and a later pass must read the same value */
static void
jnxequities_pts_itch_anchor_begin(packet_info *pinfo)
{
    uint64_t *seconds = (uint64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_jnxequities_pts_itch, 0);

    if (seconds == NULL) {
        seconds = wmem_new0(wmem_file_scope(), uint64_t);
        *seconds = jnxequities_pts_itch_conversation_of(pinfo)->seconds;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_jnxequities_pts_itch, 0, seconds);
    }

    jnxequities_pts_itch_anchor = *seconds;
}

/* The feed established a second, the messages after it count from it */
static void
jnxequities_pts_itch_anchor_set(packet_info *pinfo, uint64_t seconds)
{
    jnxequities_pts_itch_anchor = seconds;

    if (!pinfo->fd->visited) {
        jnxequities_pts_itch_conversation_of(pinfo)->seconds = seconds;
    }
}

/* Date a count from midnight by the frame that carried it. The day is
   settled once per frame, from the first time of day read out of it: the
   messages a frame carries share the day it arrived, and a later pass over
   the frame must read what the first one settled on */
static void
jnxequities_pts_itch_utc(packet_info *pinfo, uint64_t seconds, uint32_t nanoseconds, nstime_t *instant)
{
    int64_t *midnight = (int64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_jnxequities_pts_itch, 1);

    if (midnight == NULL) {
        int64_t settled = (int64_t)pinfo->abs_ts.secs - (int64_t)seconds;

        midnight = wmem_new0(wmem_file_scope(), int64_t);
        *midnight = (settled + (settled < 0 ? -450 : 450)) / 900 * 900;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_jnxequities_pts_itch, 1, midnight);
    }

    instant->secs = (time_t)(*midnight + (int64_t)seconds);
    instant->nsecs = (int)nanoseconds;
}

/* Cap the fraction at the preferred decimal places */
static void
jnxequities_pts_itch_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = jnxequities_pts_itch_pref_decimal_places;

    if (places >= strlen(point + 1)) {
        return;
    }

    if (places == 0) {
        *point = '\0';
        return;
    }

    point[1 + places] = '\0';
}

/* Format an implied 1 decimal place value */
static void
jnxequities_pts_itch_format_decimal_1_32_unsigned(char *buf, uint32_t raw)
{
    uint64_t value = (uint32_t)raw;
    uint64_t units = value / 10;
    uint64_t fraction = value % 10;

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRIu64 ".%01" PRIu64, units, fraction);

    jnxequities_pts_itch_decimal_places(buf);
}

/*
 * JnxEquities Pts Fields
 */

/* Accepted Sequence Number */
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_NAME        "Accepted Sequence Number"
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION "The sequence number in ASCII of the next Sequenced Message to be sent. Left padded with spaces."
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_FILTER      "jnxequities.pts.itch.acceptedsequencenumber"
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_jnxequities_pts_itch_accepted_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_jnxequities_pts_itch_accepted_sequence_number, tvb, offset, JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_SIZE, value);

    return offset + JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_SIZE;
}

/* Accepted Session */
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_NAME        "Accepted Session"
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_DESCRIPTION "The session ID of the session that is now logged into. Left padded with spaces."
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_FILTER      "jnxequities.pts.itch.acceptedsession"
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_SIZE        10

static unsigned
parse_jnxequities_pts_itch_accepted_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_accepted_session, tvb, offset, JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_SIZE, JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_SIZE;
}

/* Attribution */
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_NAME        "Attribution"
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_DESCRIPTION "Reserved; always blank."
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_FILTER      "jnxequities.pts.itch.attribution"
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_ATTRIBUTION_SIZE        4

static unsigned
parse_jnxequities_pts_itch_attribution(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_attribution, tvb, offset, JNXEQUITIES_PTS_ITCH_ATTRIBUTION_SIZE, JNXEQUITIES_PTS_ITCH_ATTRIBUTION_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ATTRIBUTION_SIZE;
}

/* Buy Sell Indicator */
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_NAME        "Buy Sell Indicator"
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_DESCRIPTION "Side of the order."
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_FILTER      "jnxequities.pts.itch.buysellindicator"
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_SIZE        1

static const value_string jnxequities_pts_itch_buy_sell_indicator_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_buy_sell_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_buy_sell_indicator, tvb, offset, JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_SIZE, JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_SIZE;
}

/* Client Packet Type values the dispatch switches on */
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET            '+'
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET    'L'
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET 'U'
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET 'R'
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET   'O'

/* Client Packet Type */
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_NAME        "Packet Type"
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the client"
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_FILTER      "jnxequities.pts.itch.clientpackettype"
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_SIZE        1

static const value_string jnxequities_pts_itch_client_packet_type_vals[] = {
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request Packet" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_client_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_client_packet_type, tvb, offset, JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_SIZE;
}

/* Debug Text */
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_NAME        "Debug Text"
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_DESCRIPTION "Free form human readable text"
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_FILTER      "jnxequities.pts.itch.debugtext"
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_ENCODING    ENC_NA

/* Executed Quantity */
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_NAME        "Executed Quantity"
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_DESCRIPTION "Number of shares executed."
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_FILTER      "jnxequities.pts.itch.executedquantity"
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_SIZE        4

static unsigned
parse_jnxequities_pts_itch_executed_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_executed_quantity, tvb, offset, JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_SIZE, JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_SIZE;
}

/* Group */
#define JNXEQUITIES_PTS_ITCH_GROUP_NAME        "Group"
#define JNXEQUITIES_PTS_ITCH_GROUP_DESCRIPTION "Orderbook group identifier."
#define JNXEQUITIES_PTS_ITCH_GROUP_FILTER      "jnxequities.pts.itch.group"
#define JNXEQUITIES_PTS_ITCH_GROUP_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_GROUP_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_GROUP_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_GROUP_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_GROUP_SIZE        4

static const string_string jnxequities_pts_itch_group_vals[] = {
    { "DAY", "Daytime Market" },
    { "NGHT", "Nighttime Market" },
    { "DAYX", "X Market" },
    { "DAYU", "U Market" },
    { NULL, NULL }
};

static unsigned
parse_jnxequities_pts_itch_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    char *value = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, JNXEQUITIES_PTS_ITCH_GROUP_SIZE, JNXEQUITIES_PTS_ITCH_GROUP_ENCODING);

    /* Left justified and filled with spaces */
    value = g_strchomp(value);

    proto_tree_add_string_format_value(tree, hf_jnxequities_pts_itch_group, tvb, offset, JNXEQUITIES_PTS_ITCH_GROUP_SIZE, value,
        "%s", str_to_str_wmem(pinfo->pool, value, jnxequities_pts_itch_group_vals, "Unknown (%s)"));

    return offset + JNXEQUITIES_PTS_ITCH_GROUP_SIZE;
}

/* Lower Price Limit */
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_NAME        "Lower Price Limit"
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_DESCRIPTION "Minimum tradable price."
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_FILTER      "jnxequities.pts.itch.lowerpricelimit"
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_DISPLAY     BASE_CUSTOM
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_SIZE        4

static unsigned
parse_jnxequities_pts_itch_lower_price_limit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_lower_price_limit, tvb, offset, JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_SIZE, JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_SIZE;
}

/* Match Number */
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_NAME        "Match Number"
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_DESCRIPTION "Reference number of the match."
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_FILTER      "jnxequities.pts.itch.matchnumber"
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_SIZE        8

static unsigned
parse_jnxequities_pts_itch_match_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_match_number, tvb, offset, JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_SIZE, JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_SIZE;
}

/* Message Count values the dispatch switches on */
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_HEARTBEAT      0
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_END_OF_SESSION UINT16_MAX

/* Message Count */
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_NAME        "Message Count"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_DESCRIPTION "Number of messages to follow this header"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_FILTER      "jnxequities.pts.itch.messagecount"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_TYPE        FT_UINT16
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_SIZE        2

static unsigned
parse_jnxequities_pts_itch_message_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_message_count, tvb, offset, JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_SIZE, JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_SIZE;
}

/* Message Length */
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_NAME        "Message Length"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_DESCRIPTION "Length of data message not including this field"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_FILTER      "jnxequities.pts.itch.messagelength"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_TYPE        FT_UINT16
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_jnxequities_pts_itch_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_message_length, tvb, offset, JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_SIZE, JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_SIZE;
}

/* Message Type values the dispatch switches on */
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SECONDS                               'T'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SYSTEM_EVENT                          'S'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_PRICE_TICK_SIZE                       'L'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDERBOOK_DIRECTORY                   'R'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TRADING_STATE                         'H'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE 'Y'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES        'A'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES           'F'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_EXECUTED                        'E'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_DELETED                         'D'
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_REPLACED                        'U'

/* Message Type */
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_NAME        "Message Type"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_DESCRIPTION "Code identifying this message type"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_FILTER      "jnxequities.pts.itch.messagetype"
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SIZE        1

static const value_string jnxequities_pts_itch_message_type_vals[] = {
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SECONDS, "Seconds Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_PRICE_TICK_SIZE, "Price Tick Size Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDERBOOK_DIRECTORY, "Orderbook Directory Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TRADING_STATE, "Trading State Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE, "Short Selling Price Restriction State Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES, "Order Added Without Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES, "Order Added With Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_DELETED, "Order Deleted Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_REPLACED, "Order Replaced Message" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_message_type, tvb, offset, JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SIZE;
}

/* Nanoseconds */
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_NAME        "Nanoseconds"
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_DESCRIPTION "Number of nanoseconds since last Timestamp Seconds Message."
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_FILTER      "jnxequities.pts.itch.nanoseconds"
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_TYPE        FT_RELATIVE_TIME
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_ENCODING    ENC_TIME_NSECS | ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE        4

static unsigned
parse_jnxequities_pts_itch_nanoseconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t counted = tvb_get_ntohl(tvb, offset);

    proto_tree_add_item(tree, hf_jnxequities_pts_itch_nanoseconds, tvb, offset, JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE, JNXEQUITIES_PTS_ITCH_NANOSECONDS_ENCODING);

    if (jnxequities_pts_itch_pref_read_nanoseconds) {
        /* The second the feed established composes the time of day */
        nstime_t time = {
            .secs = (time_t)(jnxequities_pts_itch_anchor + counted / 1000000000),
            .nsecs = (int)(counted % 1000000000) * 1,
        };

        nstime_t instant;

        jnxequities_pts_itch_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

        proto_item *reading = proto_tree_add_time(tree, hf_jnxequities_pts_itch_utc, tvb, offset, JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE, &instant);

        proto_item_set_generated(reading);

        /* The span since midnight the two together count out */
        uint64_t total = jnxequities_pts_itch_anchor * 1000000000 + counted;

        proto_tree *readings = proto_item_add_subtree(reading, ett_jnxequities_pts_itch_timestamp);

        char clock[32];

        jnxequities_pts_itch_time_of_day_label(clock, sizeof(clock), &time);

        proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_jnxequities_pts_itch_time_of_day, tvb, offset, JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE, &time, "%s", clock));
        proto_item_set_generated(proto_tree_add_time(readings, hf_jnxequities_pts_itch_local, tvb, offset, JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE, &instant));
        proto_tree_add_uint64(readings, hf_jnxequities_pts_itch_elapsed_nanoseconds, tvb, offset, JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE, total);

    }

    return offset + JNXEQUITIES_PTS_ITCH_NANOSECONDS_SIZE;
}

/* New Order Number */
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_NAME        "New Order Number"
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_DESCRIPTION "Reference number of the replaced order."
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_FILTER      "jnxequities.pts.itch.newordernumber"
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_SIZE        8

static unsigned
parse_jnxequities_pts_itch_new_order_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_new_order_number, tvb, offset, JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_SIZE, JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_SIZE;
}

/* Order Number */
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_NAME        "Order Number"
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_DESCRIPTION "Reference number of the accepted order; zero indicates a reference price message."
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_FILTER      "jnxequities.pts.itch.ordernumber"
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_SIZE        8

static unsigned
parse_jnxequities_pts_itch_order_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_order_number, tvb, offset, JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_SIZE, JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_SIZE;
}

/* Order Type */
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_NAME        "Order Type"
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_DESCRIPTION "Type of the order."
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_FILTER      "jnxequities.pts.itch.ordertype"
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_ORDER_TYPE_SIZE        1

static const value_string jnxequities_pts_itch_order_type_vals[] = {
    { 'Q', "Dlp Order" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_order_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_order_type, tvb, offset, JNXEQUITIES_PTS_ITCH_ORDER_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_ORDER_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ORDER_TYPE_SIZE;
}

/* Orderbook Code */
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_NAME        "Orderbook Code"
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_DESCRIPTION "International Securities Identification Number (ISIN)."
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_FILTER      "jnxequities.pts.itch.orderbookcode"
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_SIZE        12

static unsigned
parse_jnxequities_pts_itch_orderbook_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_orderbook_code, tvb, offset, JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_SIZE, JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_SIZE;
}

/* Orderbook Id */
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_NAME        "Orderbook Id"
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_DESCRIPTION "4 digit Quick code."
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_FILTER      "jnxequities.pts.itch.orderbookid"
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_SIZE        4

static unsigned
parse_jnxequities_pts_itch_orderbook_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_orderbook_id, tvb, offset, JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_SIZE, JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_SIZE;
}

/* Original Order Number */
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_NAME        "Original Order Number"
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_DESCRIPTION "Reference number of the original order."
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_FILTER      "jnxequities.pts.itch.originalordernumber"
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_SIZE        8

static unsigned
parse_jnxequities_pts_itch_original_order_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_original_order_number, tvb, offset, JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_SIZE, JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_SIZE;
}

/* Packet Length */
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_NAME        "Packet Length"
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_DESCRIPTION "Length of data message not including this field"
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_FILTER      "jnxequities.pts.itch.packetlength"
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_TYPE        FT_UINT16
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_SIZE        2

static unsigned
parse_jnxequities_pts_itch_packet_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_packet_length, tvb, offset, JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_SIZE, JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_SIZE;
}

/* Password */
#define JNXEQUITIES_PTS_ITCH_PASSWORD_NAME        "Password"
#define JNXEQUITIES_PTS_ITCH_PASSWORD_DESCRIPTION "Login password"
#define JNXEQUITIES_PTS_ITCH_PASSWORD_FILTER      "jnxequities.pts.itch.password"
#define JNXEQUITIES_PTS_ITCH_PASSWORD_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_PASSWORD_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_PASSWORD_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PASSWORD_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_PASSWORD_SIZE        10

static unsigned
parse_jnxequities_pts_itch_password(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_password, tvb, offset, JNXEQUITIES_PTS_ITCH_PASSWORD_SIZE, JNXEQUITIES_PTS_ITCH_PASSWORD_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PASSWORD_SIZE;
}

/* Price */
#define JNXEQUITIES_PTS_ITCH_PRICE_NAME        "Price"
#define JNXEQUITIES_PTS_ITCH_PRICE_DESCRIPTION "Price of the order; for a reference price message, a value of 214,748,364.7 (7FFFFFFF hex) denotes no reference price available."
#define JNXEQUITIES_PTS_ITCH_PRICE_FILTER      "jnxequities.pts.itch.price"
#define JNXEQUITIES_PTS_ITCH_PRICE_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_PRICE_DISPLAY     BASE_CUSTOM
#define JNXEQUITIES_PTS_ITCH_PRICE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PRICE_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PRICE_SIZE        4

static unsigned
parse_jnxequities_pts_itch_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_price, tvb, offset, JNXEQUITIES_PTS_ITCH_PRICE_SIZE, JNXEQUITIES_PTS_ITCH_PRICE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PRICE_SIZE;
}

/* Price Decimals */
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_NAME        "Price Decimals"
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_DESCRIPTION "Number of decimal places in price fields; value is 1."
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_FILTER      "jnxequities.pts.itch.pricedecimals"
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_SIZE        4

static unsigned
parse_jnxequities_pts_itch_price_decimals(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_price_decimals, tvb, offset, JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_SIZE, JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_SIZE;
}

/* Price Start */
#define JNXEQUITIES_PTS_ITCH_PRICE_START_NAME        "Price Start"
#define JNXEQUITIES_PTS_ITCH_PRICE_START_DESCRIPTION "Start of price range for this price tick size."
#define JNXEQUITIES_PTS_ITCH_PRICE_START_FILTER      "jnxequities.pts.itch.pricestart"
#define JNXEQUITIES_PTS_ITCH_PRICE_START_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_PRICE_START_DISPLAY     BASE_CUSTOM
#define JNXEQUITIES_PTS_ITCH_PRICE_START_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PRICE_START_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PRICE_START_SIZE        4

static unsigned
parse_jnxequities_pts_itch_price_start(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_price_start, tvb, offset, JNXEQUITIES_PTS_ITCH_PRICE_START_SIZE, JNXEQUITIES_PTS_ITCH_PRICE_START_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PRICE_START_SIZE;
}

/* Price Tick Size */
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_NAME        "Price Tick Size"
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_DESCRIPTION "Price tick size."
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_FILTER      "jnxequities.pts.itch.priceticksize"
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_DISPLAY     BASE_CUSTOM
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_SIZE        4

static unsigned
parse_jnxequities_pts_itch_price_tick_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_price_tick_size, tvb, offset, JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_SIZE, JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_SIZE;
}

/* Price Tick Size Table Id */
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_NAME        "Price Tick Size Table Id"
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_DESCRIPTION "Price tick size table identifier."
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_FILTER      "jnxequities.pts.itch.priceticksizetableid"
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_SIZE        4

static unsigned
parse_jnxequities_pts_itch_price_tick_size_table_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_price_tick_size_table_id, tvb, offset, JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_SIZE, JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_SIZE;
}

/* Quantity */
#define JNXEQUITIES_PTS_ITCH_QUANTITY_NAME        "Quantity"
#define JNXEQUITIES_PTS_ITCH_QUANTITY_DESCRIPTION "Total number of shares added to the book."
#define JNXEQUITIES_PTS_ITCH_QUANTITY_FILTER      "jnxequities.pts.itch.quantity"
#define JNXEQUITIES_PTS_ITCH_QUANTITY_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_QUANTITY_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_QUANTITY_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_QUANTITY_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_QUANTITY_SIZE        4

static unsigned
parse_jnxequities_pts_itch_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_quantity, tvb, offset, JNXEQUITIES_PTS_ITCH_QUANTITY_SIZE, JNXEQUITIES_PTS_ITCH_QUANTITY_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_QUANTITY_SIZE;
}

/* Reject Reason Code */
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_NAME        "Reject Reason Code"
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_DESCRIPTION "Login Reject Codes"
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_FILTER      "jnxequities.pts.itch.rejectreasoncode"
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_SIZE        1

static const value_string jnxequities_pts_itch_reject_reason_code_vals[] = {
    { 'A', "Not Authorized" },
    { 'S', "Session Not Available" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_reject_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_reject_reason_code, tvb, offset, JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_SIZE, JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_SIZE;
}

/* Requested Sequence Number */
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_NAME        "Requested Sequence Number"
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_FILTER      "jnxequities.pts.itch.requestedsequencenumber"
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_jnxequities_pts_itch_requested_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_jnxequities_pts_itch_requested_sequence_number, tvb, offset, JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_SIZE, value);

    return offset + JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_SIZE;
}

/* Requested Session */
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_NAME        "Requested Session"
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_DESCRIPTION "Specifies the session the client would like to log into, or all blanks to log into the currently active session."
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_FILTER      "jnxequities.pts.itch.requestedsession"
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_SIZE        10

static unsigned
parse_jnxequities_pts_itch_requested_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_requested_session, tvb, offset, JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_SIZE, JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_SIZE;
}

/* Round Lot Size */
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_NAME        "Round Lot Size"
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_DESCRIPTION "Number of shares that represent a round lot."
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_FILTER      "jnxequities.pts.itch.roundlotsize"
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_SIZE        4

static unsigned
parse_jnxequities_pts_itch_round_lot_size(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_round_lot_size, tvb, offset, JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_SIZE, JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_SIZE;
}

/* Seconds */
#define JNXEQUITIES_PTS_ITCH_SECONDS_NAME        "Seconds"
#define JNXEQUITIES_PTS_ITCH_SECONDS_DESCRIPTION "Number of seconds since midnight of the day that the trading session started."
#define JNXEQUITIES_PTS_ITCH_SECONDS_FILTER      "jnxequities.pts.itch.seconds"
#define JNXEQUITIES_PTS_ITCH_SECONDS_TYPE        FT_ABSOLUTE_TIME
#define JNXEQUITIES_PTS_ITCH_SECONDS_DISPLAY     ABSOLUTE_TIME_UTC
#define JNXEQUITIES_PTS_ITCH_SECONDS_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SECONDS_ENCODING    ENC_TIME_SECS | ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_SECONDS_SIZE        4

static unsigned
parse_jnxequities_pts_itch_seconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t seconds = tvb_get_ntohl(tvb, offset);

    /* The messages after it count from this second */
    jnxequities_pts_itch_anchor_set(pinfo, seconds);

    if (!jnxequities_pts_itch_pref_read_seconds) {
        proto_tree_add_uint64(tree, hf_jnxequities_pts_itch_elapsed_seconds, tvb, offset, JNXEQUITIES_PTS_ITCH_SECONDS_SIZE, seconds);

        return offset + JNXEQUITIES_PTS_ITCH_SECONDS_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(seconds / 1),
        .nsecs = (int)(seconds % 1) * 1000000000,
    };

    nstime_t instant;

    jnxequities_pts_itch_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_jnxequities_pts_itch_seconds, tvb, offset, JNXEQUITIES_PTS_ITCH_SECONDS_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_jnxequities_pts_itch_timestamp);

    char clock[32];

    jnxequities_pts_itch_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_jnxequities_pts_itch_time_of_day, tvb, offset, JNXEQUITIES_PTS_ITCH_SECONDS_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_jnxequities_pts_itch_local, tvb, offset, JNXEQUITIES_PTS_ITCH_SECONDS_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_jnxequities_pts_itch_elapsed_seconds, tvb, offset, JNXEQUITIES_PTS_ITCH_SECONDS_SIZE, seconds);

    return offset + JNXEQUITIES_PTS_ITCH_SECONDS_SIZE;
}

/* Sequence Number */
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_NAME        "Sequence Number"
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_DESCRIPTION "Sequence number of the first message to follow this header"
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_FILTER      "jnxequities.pts.itch.sequencenumber"
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_jnxequities_pts_itch_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_sequence_number, tvb, offset, JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_SIZE, JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_SIZE;
}

/* Sequenced Message Type values the dispatch switches on */
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TIMESTAMP_SECONDS                     'T'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT                          'S'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_PRICE_TICK_SIZE                       'L'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDERBOOK_DIRECTORY                   'R'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TRADING_STATE                         'H'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE 'Y'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES        'A'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES           'F'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED                        'E'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_DELETED                         'D'
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACED                        'U'

/* Sequenced Message Type */
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_NAME        "Sequenced Message Type"
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying sequenced message type"
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_FILTER      "jnxequities.pts.itch.sequencedmessagetype"
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SIZE        1

static const value_string jnxequities_pts_itch_sequenced_message_type_vals[] = {
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TIMESTAMP_SECONDS, "Timestamp Seconds Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_PRICE_TICK_SIZE, "Price Tick Size Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDERBOOK_DIRECTORY, "Orderbook Directory Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TRADING_STATE, "Trading State Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE, "Short Selling Price Restriction State Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES, "Order Added Without Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES, "Order Added With Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_DELETED, "Order Deleted Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACED, "Order Replaced Message" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_sequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_sequenced_message_type, tvb, offset, JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SIZE;
}

/* Server Packet Type values the dispatch switches on */
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET            '+'
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET   'A'
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET   'J'
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET   'S'
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET 'H'
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET   'Z'

/* Server Packet Type */
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_NAME        "Packet Type"
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the server"
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_FILTER      "jnxequities.pts.itch.serverpackettype"
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SIZE        1

static const value_string jnxequities_pts_itch_server_packet_type_vals[] = {
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session Packet" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_server_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_server_packet_type, tvb, offset, JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SIZE;
}

/* Session */
#define JNXEQUITIES_PTS_ITCH_SESSION_NAME        "Session"
#define JNXEQUITIES_PTS_ITCH_SESSION_DESCRIPTION "Identity of the multicast session"
#define JNXEQUITIES_PTS_ITCH_SESSION_FILTER      "jnxequities.pts.itch.session"
#define JNXEQUITIES_PTS_ITCH_SESSION_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_SESSION_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_SESSION_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SESSION_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_SESSION_SIZE        10

static unsigned
parse_jnxequities_pts_itch_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_session, tvb, offset, JNXEQUITIES_PTS_ITCH_SESSION_SIZE, JNXEQUITIES_PTS_ITCH_SESSION_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SESSION_SIZE;
}

/* Short Selling State */
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_NAME        "Short Selling State"
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_DESCRIPTION "Current short selling price restriction state; values: 0 = No price restriction, 1 = Price restriction in effect."
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_FILTER      "jnxequities.pts.itch.shortsellingstate"
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_SIZE        1

static const value_string jnxequities_pts_itch_short_selling_state_vals[] = {
    { '0', "No Price Restriction" },
    { '1', "Price Restriction In Effect" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_short_selling_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_short_selling_state, tvb, offset, JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_SIZE, JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_SIZE;
}

/* System Event */
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_NAME        "System Event"
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_DESCRIPTION "Refer to the System Events table below."
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_FILTER      "jnxequities.pts.itch.systemevent"
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_SIZE        1

static const value_string jnxequities_pts_itch_system_event_vals[] = {
    { 'O', "Start Of Messages" },
    { 'S', "Start Of System Hours" },
    { 'Q', "Start Of Market Hours" },
    { 'M', "End Of Market Hours" },
    { 'E', "End Of System Hours" },
    { 'C', "End Of Messages" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_system_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_system_event, tvb, offset, JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_SIZE, JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_SIZE;
}

/* Trading State */
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_NAME        "Trading State"
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_DESCRIPTION "Current trading state."
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_FILTER      "jnxequities.pts.itch.tradingstate"
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_TRADING_STATE_SIZE        1

static const value_string jnxequities_pts_itch_trading_state_vals[] = {
    { 'T', "Trading" },
    { 'V', "Suspended" },
    { 0, NULL }
};

static unsigned
parse_jnxequities_pts_itch_trading_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_trading_state, tvb, offset, JNXEQUITIES_PTS_ITCH_TRADING_STATE_SIZE, JNXEQUITIES_PTS_ITCH_TRADING_STATE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_TRADING_STATE_SIZE;
}

/* Unsequenced Message */
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_NAME        "Unsequenced Message"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_DESCRIPTION "The unsequenced (client to server) message carried by the packet, opaque bytes unless an application source dispatches it"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_FILTER      "jnxequities.pts.itch.unsequencedmessage"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE        FT_BYTES
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_ENCODING    ENC_NA

/* Unsequenced Message Type */
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_NAME        "Unsequenced Message Type"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying unsequenced message type"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_FILTER      "jnxequities.pts.itch.unsequencedmessagetype"
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_SIZE        1

static unsigned
parse_jnxequities_pts_itch_unsequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_unsequenced_message_type, tvb, offset, JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_SIZE, JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_SIZE;
}

/* Upper Price Limit */
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_NAME        "Upper Price Limit"
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_DESCRIPTION "Maximum tradable price."
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_FILTER      "jnxequities.pts.itch.upperpricelimit"
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_TYPE        FT_UINT32
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_DISPLAY     BASE_CUSTOM
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_ENCODING    ENC_BIG_ENDIAN
#define JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_SIZE        4

static unsigned
parse_jnxequities_pts_itch_upper_price_limit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_upper_price_limit, tvb, offset, JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_SIZE, JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_SIZE;
}

/* Username */
#define JNXEQUITIES_PTS_ITCH_USERNAME_NAME        "Username"
#define JNXEQUITIES_PTS_ITCH_USERNAME_DESCRIPTION "Session username"
#define JNXEQUITIES_PTS_ITCH_USERNAME_FILTER      "jnxequities.pts.itch.username"
#define JNXEQUITIES_PTS_ITCH_USERNAME_TYPE        FT_STRING
#define JNXEQUITIES_PTS_ITCH_USERNAME_DISPLAY     BASE_NONE
#define JNXEQUITIES_PTS_ITCH_USERNAME_MASK        0x0
#define JNXEQUITIES_PTS_ITCH_USERNAME_ENCODING    ENC_ASCII
#define JNXEQUITIES_PTS_ITCH_USERNAME_SIZE        6

static unsigned
parse_jnxequities_pts_itch_username(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_jnxequities_pts_itch_username, tvb, offset, JNXEQUITIES_PTS_ITCH_USERNAME_SIZE, JNXEQUITIES_PTS_ITCH_USERNAME_ENCODING);

    return offset + JNXEQUITIES_PTS_ITCH_USERNAME_SIZE;
}

/*
 * JnxEquities Pts Structs
 */

/* Message and group dissect methods */
static unsigned dissect_jnxequities_pts_itch_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_debug_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_seconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_price_tick_size(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_orderbook_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_trading_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_short_selling_price_restriction_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_order_added_without_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_order_added_with_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_order_deleted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_jnxequities_pts_itch_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_jnxequities_pts_itch_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_jnxequities_pts_itch_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_jnxequities_pts_itch_packet_udp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);

/* Client Packet Header */
static unsigned
dissect_jnxequities_pts_itch_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (jnxequities_pts_itch_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_jnxequities_pts_itch_client_packet_header, &item, "Client Packet Header");
    }

    unsigned start = offset;

    offset = parse_jnxequities_pts_itch_packet_length(tvb, pinfo, group, offset);
    offset = parse_jnxequities_pts_itch_client_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Debug Packet */
static unsigned
dissect_jnxequities_pts_itch_debug_packet(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, unsigned offset)
{
    /* Debug Text is a placeholder, it consumes no bytes */

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_jnxequities_pts_itch_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_username(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_password(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_requested_session(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_requested_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Unsequenced Data Packet */
static unsigned
dissect_jnxequities_pts_itch_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_unsequenced_message_type(tvb, pinfo, tree, offset);
    /* Unsequenced Message is a placeholder, it consumes no bytes */

    return offset;
}

/* Server Packet Header */
static unsigned
dissect_jnxequities_pts_itch_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (jnxequities_pts_itch_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_jnxequities_pts_itch_server_packet_header, &item, "Server Packet Header");
    }

    unsigned start = offset;

    offset = parse_jnxequities_pts_itch_packet_length(tvb, pinfo, group, offset);
    offset = parse_jnxequities_pts_itch_server_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_jnxequities_pts_itch_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_accepted_session(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_accepted_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Rejected Packet */
static unsigned
dissect_jnxequities_pts_itch_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_reject_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_jnxequities_pts_itch_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_jnxequities_pts_itch_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_jnxequities_pts_itch_sequenced_message(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* Seconds Message */
static unsigned
dissect_jnxequities_pts_itch_seconds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_seconds(tvb, pinfo, tree, offset);

    return offset;
}

/* System Event Message */
static unsigned
dissect_jnxequities_pts_itch_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_system_event(tvb, pinfo, tree, offset);

    return offset;
}

/* Price Tick Size Message */
static unsigned
dissect_jnxequities_pts_itch_price_tick_size(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price_tick_size_table_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price_tick_size(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price_start(tvb, pinfo, tree, offset);

    return offset;
}

/* Orderbook Directory Message */
static unsigned
dissect_jnxequities_pts_itch_orderbook_directory(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_code(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_round_lot_size(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price_tick_size_table_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price_decimals(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_upper_price_limit(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_lower_price_limit(tvb, pinfo, tree, offset);

    return offset;
}

/* Trading State Message */
static unsigned
dissect_jnxequities_pts_itch_trading_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_trading_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Short Selling Price Restriction State Message */
static unsigned
dissect_jnxequities_pts_itch_short_selling_price_restriction_state(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_short_selling_state(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Added Without Attributes Message */
static unsigned
dissect_jnxequities_pts_itch_order_added_without_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_order_number(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_quantity(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Added With Attributes Message */
static unsigned
dissect_jnxequities_pts_itch_order_added_with_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_order_number(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_quantity(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_orderbook_id(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_group(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_attribution(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_order_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_jnxequities_pts_itch_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_order_number(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_executed_quantity(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Deleted Message */
static unsigned
dissect_jnxequities_pts_itch_order_deleted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_order_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replaced Message */
static unsigned
dissect_jnxequities_pts_itch_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_jnxequities_pts_itch_nanoseconds(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_original_order_number(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_new_order_number(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_quantity(tvb, pinfo, tree, offset);
    offset = parse_jnxequities_pts_itch_price(tvb, pinfo, tree, offset);

    return offset;
}

/* Message Header */
static unsigned
dissect_jnxequities_pts_itch_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (jnxequities_pts_itch_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_jnxequities_pts_itch_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_jnxequities_pts_itch_message_length(tvb, pinfo, group, offset);
    offset = parse_jnxequities_pts_itch_message_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/*
 * JnxEquities Pts Parse Trees, a dispatch per distinct branch definition
 */

static const value_string jnxequities_pts_itch_client_packet_messages[] = {
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat Packet" },
    { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request Packet" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_jnxequities_pts_itch_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, jnxequities_pts_itch_client_packet_messages, "Unknown (%u)"));

    switch (client_packet_type) {
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_jnxequities_pts_itch_debug_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_jnxequities_pts_itch_login_request_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_jnxequities_pts_itch_unsequenced_data_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat Packet */
        return offset;
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request Packet */
        return offset;
    }

    return offset;
}

static const value_string jnxequities_pts_itch_server_packet_messages[] = {
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat Packet" },
    { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session Packet" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_jnxequities_pts_itch_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, jnxequities_pts_itch_server_packet_messages, "Unknown (%u)"));

    switch (server_packet_type) {
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_jnxequities_pts_itch_debug_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_jnxequities_pts_itch_login_accepted_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_jnxequities_pts_itch_login_rejected_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_jnxequities_pts_itch_sequenced_data_packet(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat Packet */
        return offset;
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session Packet */
        return offset;
    }

    return offset;
}

static const value_string jnxequities_pts_itch_sequenced_message_messages[] = {
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TIMESTAMP_SECONDS, "Seconds Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_PRICE_TICK_SIZE, "Price Tick Size Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDERBOOK_DIRECTORY, "Orderbook Directory Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TRADING_STATE, "Trading State Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE, "Short Selling Price Restriction State Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES, "Order Added Without Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES, "Order Added With Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_DELETED, "Order Deleted Message" },
    { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACED, "Order Replaced Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_jnxequities_pts_itch_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, jnxequities_pts_itch_sequenced_message_messages, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TIMESTAMP_SECONDS:
        return dissect_jnxequities_pts_itch_seconds(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_jnxequities_pts_itch_system_event(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_PRICE_TICK_SIZE:
        return dissect_jnxequities_pts_itch_price_tick_size(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDERBOOK_DIRECTORY:
        return dissect_jnxequities_pts_itch_orderbook_directory(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TRADING_STATE:
        return dissect_jnxequities_pts_itch_trading_state(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE:
        return dissect_jnxequities_pts_itch_short_selling_price_restriction_state(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES:
        return dissect_jnxequities_pts_itch_order_added_without_attributes(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES:
        return dissect_jnxequities_pts_itch_order_added_with_attributes(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_jnxequities_pts_itch_order_executed(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_DELETED:
        return dissect_jnxequities_pts_itch_order_deleted(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_ORDER_REPLACED:
        return dissect_jnxequities_pts_itch_order_replaced(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string jnxequities_pts_itch_packet_messages[] = {
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SECONDS, "Seconds Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_PRICE_TICK_SIZE, "Price Tick Size Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDERBOOK_DIRECTORY, "Orderbook Directory Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TRADING_STATE, "Trading State Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE, "Short Selling Price Restriction State Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES, "Order Added Without Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES, "Order Added With Attributes Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_DELETED, "Order Deleted Message" },
    { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_REPLACED, "Order Replaced Message" },
    { 0, NULL }
};

/* Udp Payload: dispatch on message_type */
static unsigned
dissect_jnxequities_pts_itch_packet_udp_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type)
{
    switch (message_type) {
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SECONDS:
        return dissect_jnxequities_pts_itch_seconds(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_jnxequities_pts_itch_system_event(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_PRICE_TICK_SIZE:
        return dissect_jnxequities_pts_itch_price_tick_size(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDERBOOK_DIRECTORY:
        return dissect_jnxequities_pts_itch_orderbook_directory(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TRADING_STATE:
        return dissect_jnxequities_pts_itch_trading_state(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE:
        return dissect_jnxequities_pts_itch_short_selling_price_restriction_state(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES:
        return dissect_jnxequities_pts_itch_order_added_without_attributes(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES:
        return dissect_jnxequities_pts_itch_order_added_with_attributes(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_jnxequities_pts_itch_order_executed(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_DELETED:
        return dissect_jnxequities_pts_itch_order_deleted(tvb, pinfo, tree, offset);
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_REPLACED:
        return dissect_jnxequities_pts_itch_order_replaced(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
jnxequities_pts_itch_client_packet_show(uint32_t client_packet_type)
{
    switch (client_packet_type) {
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    }

    return true;
}

typedef struct jnxequities_pts_itch_client_packet_parse jnxequities_pts_itch_client_packet_parse;

struct jnxequities_pts_itch_client_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
};

static const jnxequities_pts_itch_client_packet_parse jnxequities_pts_itch_client_packet_parse_v17 = { jnxequities_pts_itch_client_packet_messages, dissect_jnxequities_pts_itch_client_packet_client_payload };

/* Parse tree of the selected version */
static const jnxequities_pts_itch_client_packet_parse *
jnxequities_pts_itch_client_packet_parse_for(int version)
{
    switch (version) {
    default:
        return &jnxequities_pts_itch_client_packet_parse_v17;
    }
}

/* Show preference of the dispatched message */
static bool
jnxequities_pts_itch_server_packet_show(uint32_t server_packet_type)
{
    switch (server_packet_type) {
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return jnxequities_pts_itch_show_session_messages;
    }

    return true;
}

typedef struct jnxequities_pts_itch_server_packet_parse jnxequities_pts_itch_server_packet_parse;

struct jnxequities_pts_itch_server_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
};

static const jnxequities_pts_itch_server_packet_parse jnxequities_pts_itch_server_packet_parse_v17 = { jnxequities_pts_itch_server_packet_messages, dissect_jnxequities_pts_itch_server_packet_server_payload };

/* Parse tree of the selected version */
static const jnxequities_pts_itch_server_packet_parse *
jnxequities_pts_itch_server_packet_parse_for(int version)
{
    switch (version) {
    default:
        return &jnxequities_pts_itch_server_packet_parse_v17;
    }
}

/* Show preference of the dispatched message */
static bool
jnxequities_pts_itch_packet_show(uint32_t message_type)
{
    switch (message_type) {
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SECONDS:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SYSTEM_EVENT:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_PRICE_TICK_SIZE:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDERBOOK_DIRECTORY:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TRADING_STATE:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_SHORT_SELLING_PRICE_RESTRICTION_STATE:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITHOUT_ATTRIBUTES:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_ADDED_WITH_ATTRIBUTES:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_EXECUTED:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_DELETED:
        return jnxequities_pts_itch_show_application_messages;
    case JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_ORDER_REPLACED:
        return jnxequities_pts_itch_show_application_messages;
    }

    return true;
}

typedef struct jnxequities_pts_itch_packet_parse jnxequities_pts_itch_packet_parse;

struct jnxequities_pts_itch_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t message_type);
};

static const jnxequities_pts_itch_packet_parse jnxequities_pts_itch_packet_parse_v17 = { jnxequities_pts_itch_packet_messages, dissect_jnxequities_pts_itch_packet_udp_payload };

/* Parse tree of the selected version */
static const jnxequities_pts_itch_packet_parse *
jnxequities_pts_itch_packet_parse_for(int version)
{
    switch (version) {
    default:
        return &jnxequities_pts_itch_packet_parse_v17;
    }
}

/* Is the port the acceptor's, by preference or by the declared ports? */
static bool
jnxequities_pts_itch_acceptor_port(uint32_t port)
{
    return port != 0 && (port == jnxequities_pts_itch_pref_acceptor_port || port == 11002 || port == 15001 || port == 15002);
}

/* Connection role of the frame's sender */
static int
jnxequities_pts_itch_role(packet_info *pinfo)
{
    if (jnxequities_pts_itch_pref_assume_role != JNXEQUITIES_PTS_ITCH_ROLE_RESOLVE) {
        return jnxequities_pts_itch_pref_assume_role;
    }

    if (jnxequities_pts_itch_acceptor_port(pinfo->destport)) {
        return JNXEQUITIES_PTS_ITCH_ROLE_INITIATOR;
    }

    if (jnxequities_pts_itch_acceptor_port(pinfo->srcport)) {
        return JNXEQUITIES_PTS_ITCH_ROLE_ACCEPTOR;
    }

    jnxequities_pts_itch_conversation *session = jnxequities_pts_itch_conversation_of(pinfo);

    bool first = pinfo->srcport == session->port
        && addresses_equal(&pinfo->src, &session->initiator);

    if (jnxequities_pts_itch_pref_swap_sides) {
        first = !first;
    }

    if (session->swapped) {
        first = !first;
    }

    return first ? JNXEQUITIES_PTS_ITCH_ROLE_INITIATOR : JNXEQUITIES_PTS_ITCH_ROLE_ACCEPTOR;
}

/* Swap the resolved sides of the frame's conversation */
static void
jnxequities_pts_itch_swap(packet_info *pinfo)
{
    jnxequities_pts_itch_conversation *session = jnxequities_pts_itch_conversation_of(pinfo);

    session->swapped = !session->swapped;
}

/* JnxEquities Pts message size adjusts the declared length */
#define JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_jnxequities_pts_itch_client_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const jnxequities_pts_itch_client_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t client_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, client_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = jnxequities_pts_itch_client_packet_show(client_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT, ett_jnxequities_pts_itch_message, NULL, "%s ('%c')", name, (char)client_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_jnxequities_pts_itch_client_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, client_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_jnxequities_pts_itch_length);
    }

    return packet_length + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_jnxequities_pts_itch_client_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const jnxequities_pts_itch_client_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_jnxequities_pts_itch_client_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Client Packet: header then counted messages */
static int
dissect_jnxequities_pts_itch_client_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, JNXEQUITIES_PTS_ITCH_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_jnxequities_pts_itch, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_jnxequities_pts_itch);

    jnxequities_pts_itch_anchor_begin(pinfo);

    proto_item_append_text(item, ", Client");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Client");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = jnxequities_pts_itch_version(seconds);

    proto_item_append_text(item, " %s", jnxequities_pts_itch_version_name(version));

    const jnxequities_pts_itch_client_packet_parse *parse = jnxequities_pts_itch_client_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_jnxequities_pts_itch_client_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* JnxEquities Pts message size adjusts the declared length */
#define JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_jnxequities_pts_itch_server_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const jnxequities_pts_itch_server_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t server_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, server_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = jnxequities_pts_itch_server_packet_show(server_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT, ett_jnxequities_pts_itch_message, NULL, "%s ('%c')", name, (char)server_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_jnxequities_pts_itch_server_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, server_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_jnxequities_pts_itch_length);
    }

    return packet_length + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_jnxequities_pts_itch_server_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const jnxequities_pts_itch_server_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_jnxequities_pts_itch_server_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Server Packet: header then counted messages */
static int
dissect_jnxequities_pts_itch_server_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, JNXEQUITIES_PTS_ITCH_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_jnxequities_pts_itch, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_jnxequities_pts_itch);

    jnxequities_pts_itch_anchor_begin(pinfo);

    proto_item_append_text(item, ", Server");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Server");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = jnxequities_pts_itch_version(seconds);

    proto_item_append_text(item, " %s", jnxequities_pts_itch_version_name(version));

    const jnxequities_pts_itch_server_packet_parse *parse = jnxequities_pts_itch_server_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_jnxequities_pts_itch_server_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* Packet Header */
static unsigned
dissect_jnxequities_pts_itch_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_tree *header = proto_tree_add_subtree(tree, tvb, offset, JNXEQUITIES_PTS_ITCH_PACKET_HEADER_SIZE,
        ett_jnxequities_pts_itch_header, NULL, "Packet Header");

    offset = parse_jnxequities_pts_itch_session(tvb, pinfo, header, offset);
    offset = parse_jnxequities_pts_itch_sequence_number(tvb, pinfo, header, offset);
    offset = parse_jnxequities_pts_itch_message_count(tvb, pinfo, header, offset);

    return offset;
}

/* JnxEquities Pts message size adjusts the declared length */
#define JNXEQUITIES_PTS_ITCH_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_jnxequities_pts_itch_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const jnxequities_pts_itch_packet_parse *parse)
{
    uint32_t message_length = tvb_get_ntohs(tvb, offset);
    uint32_t message_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, message_type, parse->messages, "Unknown (%u)");

    proto_tree *message = jnxequities_pts_itch_packet_show(message_type)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length + JNXEQUITIES_PTS_ITCH_PACKET_MESSAGE_ADJUSTMENT, ett_jnxequities_pts_itch_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_jnxequities_pts_itch_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, message_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length + JNXEQUITIES_PTS_ITCH_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_jnxequities_pts_itch_length);
    }

    return message_length + JNXEQUITIES_PTS_ITCH_PACKET_MESSAGE_ADJUSTMENT;
}

/* Counted messages, returns the position after the last message */
static unsigned
dissect_jnxequities_pts_itch_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t count, const jnxequities_pts_itch_packet_parse *parse)
{
    for (uint32_t index = 0; index < count; index++) {
        offset += dissect_jnxequities_pts_itch_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_jnxequities_pts_itch_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, JNXEQUITIES_PTS_ITCH_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_jnxequities_pts_itch, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_jnxequities_pts_itch);

    jnxequities_pts_itch_anchor_begin(pinfo);

    uint32_t count = tvb_get_ntohs(tvb, 18);
    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = jnxequities_pts_itch_version(seconds);

    proto_item_append_text(item, " %s", jnxequities_pts_itch_version_name(version));

    const jnxequities_pts_itch_packet_parse *parse = jnxequities_pts_itch_packet_parse_for(version);
    unsigned position = dissect_jnxequities_pts_itch_packet_header(tvb, pinfo, packet, 0);

    if (count == 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Heartbeat");
        return tvb_captured_length(tvb);
    }

    if (count == 65535) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "End Of Session");
        return tvb_captured_length(tvb);
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%u %s", count, count == 1 ? "Message" : "Messages");

    position = dissect_jnxequities_pts_itch_packet_messages(tvb, pinfo, packet, position, count, parse);

    return (int)position;
}

static bool jnxequities_pts_itch_client_packet_heur_fingerprint(tvbuff_t *tvb);
static bool jnxequities_pts_itch_server_packet_heur_fingerprint(tvbuff_t *tvb);

/* Packet: the side of the transport and the sender's connection role */
static int
dissect_jnxequities_pts_itch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (pinfo->ptype == PT_TCP) {
        if (jnxequities_pts_itch_role(pinfo) == JNXEQUITIES_PTS_ITCH_ROLE_INITIATOR) {
            if (!jnxequities_pts_itch_client_packet_heur_fingerprint(tvb) && jnxequities_pts_itch_server_packet_heur_fingerprint(tvb)) {
                jnxequities_pts_itch_swap(pinfo);

                return dissect_jnxequities_pts_itch_server_packet(tvb, pinfo, tree, data);
            }

            return dissect_jnxequities_pts_itch_client_packet(tvb, pinfo, tree, data);
        }

        if (!jnxequities_pts_itch_server_packet_heur_fingerprint(tvb) && jnxequities_pts_itch_client_packet_heur_fingerprint(tvb)) {
            jnxequities_pts_itch_swap(pinfo);

            return dissect_jnxequities_pts_itch_client_packet(tvb, pinfo, tree, data);
        }

        return dissect_jnxequities_pts_itch_server_packet(tvb, pinfo, tree, data);
    }

    return dissect_jnxequities_pts_itch_packet(tvb, pinfo, tree, data);
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define JNXEQUITIES_PTS_ITCH_MINIMUM_SIZE 3

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
jnxequities_pts_itch_heur_port(packet_info *pinfo)
{
    return value_is_in_range(jnxequities_pts_itch_pref_ports, pinfo->destport)
        || value_is_in_range(jnxequities_pts_itch_pref_ports, pinfo->srcport);
}

/* The first frame's declared length fits the stream */
static bool
jnxequities_pts_itch_client_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Fingerprint of Client Packet: would its message dispatch accept the frame? */
static bool
jnxequities_pts_itch_client_packet_heur_fingerprint(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t client_packet_type = tvb_get_uint8(tvb, 2);

    switch (client_packet_type) {
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET: /* Login Request Packet */
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET: /* Unsequenced Data Packet */
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat Packet */
    case JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request Packet */
        return true;
    }

    return false;
}

/* Does the frame pass every test of Client Packet? */
static bool
jnxequities_pts_itch_client_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!jnxequities_pts_itch_heur_port(pinfo)) {
        return false;
    }

    if (!jnxequities_pts_itch_client_packet_heur_frame(tvb)) {
        return false;
    }

    if (!jnxequities_pts_itch_client_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* The first frame's declared length fits the stream */
static bool
jnxequities_pts_itch_server_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + JNXEQUITIES_PTS_ITCH_SERVER_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= JNXEQUITIES_PTS_ITCH_SERVER_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Fingerprint of Server Packet: would its message dispatch accept the frame? */
static bool
jnxequities_pts_itch_server_packet_heur_fingerprint(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t server_packet_type = tvb_get_uint8(tvb, 2);

    switch (server_packet_type) {
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET: /* Login Accepted Packet */
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET: /* Login Rejected Packet */
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET: /* Sequenced Data Packet */
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat Packet */
    case JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session Packet */
        return true;
    }

    return false;
}

/* Does the frame pass every test of Server Packet? */
static bool
jnxequities_pts_itch_server_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!jnxequities_pts_itch_heur_port(pinfo)) {
        return false;
    }

    if (!jnxequities_pts_itch_server_packet_heur_frame(tvb)) {
        return false;
    }

    if (!jnxequities_pts_itch_server_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* The frame must hold a complete header */
static bool
jnxequities_pts_itch_packet_heur_header(tvbuff_t *tvb)
{
    return tvb_captured_length(tvb) >= JNXEQUITIES_PTS_ITCH_PACKET_HEADER_SIZE;
}

/* Does the frame pass every test of Packet? */
static bool
jnxequities_pts_itch_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!jnxequities_pts_itch_heur_port(pinfo)) {
        return false;
    }

    if (!jnxequities_pts_itch_packet_heur_header(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on, by the side of the sender's
   connection role, the other side may have sent the conversation's first frame */
static bool
dissect_jnxequities_pts_itch_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < JNXEQUITIES_PTS_ITCH_MINIMUM_SIZE) {
        return false;
    }

    bool (*first)(tvbuff_t *, packet_info *) = jnxequities_pts_itch_client_packet_heur_accepts;
    bool (*second)(tvbuff_t *, packet_info *) = jnxequities_pts_itch_server_packet_heur_accepts;

    if (jnxequities_pts_itch_role(pinfo) == JNXEQUITIES_PTS_ITCH_ROLE_ACCEPTOR) {
        first = second;
        second = jnxequities_pts_itch_client_packet_heur_accepts;
    }

    if (first(tvb, pinfo)) {
        dissect_jnxequities_pts_itch(tvb, pinfo, tree, data);
        return true;
    }

    jnxequities_pts_itch_swap(pinfo);

    if (second(tvb, pinfo)) {
        dissect_jnxequities_pts_itch(tvb, pinfo, tree, data);
        return true;
    }

    jnxequities_pts_itch_swap(pinfo);

    return false;
}

/* Recognize the protocol by the port it travels on */
static bool
dissect_jnxequities_pts_itch_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < JNXEQUITIES_PTS_ITCH_MINIMUM_SIZE) {
        return false;
    }

    if (!jnxequities_pts_itch_packet_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_jnxequities_pts_itch(tvb, pinfo, tree, data);

    return true;
}

/*
 * JnxEquities Pts Registration
 */

void
proto_register_jnxequities_pts_itch(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_jnxequities_pts_itch_accepted_sequence_number,
            { JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_accepted_session,
            { JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_NAME,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_FILTER,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_TYPE,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_MASK,
              JNXEQUITIES_PTS_ITCH_ACCEPTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_attribution,
            { JNXEQUITIES_PTS_ITCH_ATTRIBUTION_NAME,
              JNXEQUITIES_PTS_ITCH_ATTRIBUTION_FILTER,
              JNXEQUITIES_PTS_ITCH_ATTRIBUTION_TYPE,
              JNXEQUITIES_PTS_ITCH_ATTRIBUTION_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ATTRIBUTION_MASK,
              JNXEQUITIES_PTS_ITCH_ATTRIBUTION_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_buy_sell_indicator,
            { JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_NAME,
              JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_FILTER,
              JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_TYPE,
              JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_DISPLAY,
              VALS(jnxequities_pts_itch_buy_sell_indicator_vals),
              JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_MASK,
              JNXEQUITIES_PTS_ITCH_BUY_SELL_INDICATOR_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_client_packet_type,
            { JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DISPLAY,
              VALS(jnxequities_pts_itch_client_packet_type_vals),
              JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_CLIENT_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_debug_text,
            { JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_NAME,
              JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_FILTER,
              JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_TYPE,
              JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_MASK,
              JNXEQUITIES_PTS_ITCH_DEBUG_TEXT_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_executed_quantity,
            { JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_NAME,
              JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_FILTER,
              JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_TYPE,
              JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_MASK,
              JNXEQUITIES_PTS_ITCH_EXECUTED_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_group,
            { JNXEQUITIES_PTS_ITCH_GROUP_NAME,
              JNXEQUITIES_PTS_ITCH_GROUP_FILTER,
              JNXEQUITIES_PTS_ITCH_GROUP_TYPE,
              JNXEQUITIES_PTS_ITCH_GROUP_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_GROUP_MASK,
              JNXEQUITIES_PTS_ITCH_GROUP_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_lower_price_limit,
            { JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_NAME,
              JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_FILTER,
              JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_TYPE,
              JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_DISPLAY,
              CF_FUNC(jnxequities_pts_itch_format_decimal_1_32_unsigned),
              JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_MASK,
              JNXEQUITIES_PTS_ITCH_LOWER_PRICE_LIMIT_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_match_number,
            { JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_MATCH_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_message_count,
            { JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_NAME,
              JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_FILTER,
              JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_TYPE,
              JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_MASK,
              JNXEQUITIES_PTS_ITCH_MESSAGE_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_message_length,
            { JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_NAME,
              JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_FILTER,
              JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_TYPE,
              JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_MASK,
              JNXEQUITIES_PTS_ITCH_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_message_type,
            { JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_DISPLAY,
              VALS(jnxequities_pts_itch_message_type_vals),
              JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_nanoseconds,
            { JNXEQUITIES_PTS_ITCH_NANOSECONDS_NAME,
              JNXEQUITIES_PTS_ITCH_NANOSECONDS_FILTER,
              JNXEQUITIES_PTS_ITCH_NANOSECONDS_TYPE,
              JNXEQUITIES_PTS_ITCH_NANOSECONDS_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_NANOSECONDS_MASK,
              JNXEQUITIES_PTS_ITCH_NANOSECONDS_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_new_order_number,
            { JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_NEW_ORDER_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_order_number,
            { JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_ORDER_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_order_type,
            { JNXEQUITIES_PTS_ITCH_ORDER_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_ORDER_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_ORDER_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_ORDER_TYPE_DISPLAY,
              VALS(jnxequities_pts_itch_order_type_vals),
              JNXEQUITIES_PTS_ITCH_ORDER_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_ORDER_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_orderbook_code,
            { JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_NAME,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_FILTER,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_TYPE,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_MASK,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_CODE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_orderbook_id,
            { JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_NAME,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_FILTER,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_TYPE,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_MASK,
              JNXEQUITIES_PTS_ITCH_ORDERBOOK_ID_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_original_order_number,
            { JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_ORIGINAL_ORDER_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_packet_length,
            { JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_NAME,
              JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_FILTER,
              JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_TYPE,
              JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_MASK,
              JNXEQUITIES_PTS_ITCH_PACKET_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_password,
            { JNXEQUITIES_PTS_ITCH_PASSWORD_NAME,
              JNXEQUITIES_PTS_ITCH_PASSWORD_FILTER,
              JNXEQUITIES_PTS_ITCH_PASSWORD_TYPE,
              JNXEQUITIES_PTS_ITCH_PASSWORD_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_PASSWORD_MASK,
              JNXEQUITIES_PTS_ITCH_PASSWORD_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_price,
            { JNXEQUITIES_PTS_ITCH_PRICE_NAME,
              JNXEQUITIES_PTS_ITCH_PRICE_FILTER,
              JNXEQUITIES_PTS_ITCH_PRICE_TYPE,
              JNXEQUITIES_PTS_ITCH_PRICE_DISPLAY,
              CF_FUNC(jnxequities_pts_itch_format_decimal_1_32_unsigned),
              JNXEQUITIES_PTS_ITCH_PRICE_MASK,
              JNXEQUITIES_PTS_ITCH_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_price_decimals,
            { JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_NAME,
              JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_FILTER,
              JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_TYPE,
              JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_MASK,
              JNXEQUITIES_PTS_ITCH_PRICE_DECIMALS_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_price_start,
            { JNXEQUITIES_PTS_ITCH_PRICE_START_NAME,
              JNXEQUITIES_PTS_ITCH_PRICE_START_FILTER,
              JNXEQUITIES_PTS_ITCH_PRICE_START_TYPE,
              JNXEQUITIES_PTS_ITCH_PRICE_START_DISPLAY,
              CF_FUNC(jnxequities_pts_itch_format_decimal_1_32_unsigned),
              JNXEQUITIES_PTS_ITCH_PRICE_START_MASK,
              JNXEQUITIES_PTS_ITCH_PRICE_START_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_price_tick_size,
            { JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_NAME,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_FILTER,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TYPE,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_DISPLAY,
              CF_FUNC(jnxequities_pts_itch_format_decimal_1_32_unsigned),
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_MASK,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_price_tick_size_table_id,
            { JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_NAME,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_FILTER,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_TYPE,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_MASK,
              JNXEQUITIES_PTS_ITCH_PRICE_TICK_SIZE_TABLE_ID_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_quantity,
            { JNXEQUITIES_PTS_ITCH_QUANTITY_NAME,
              JNXEQUITIES_PTS_ITCH_QUANTITY_FILTER,
              JNXEQUITIES_PTS_ITCH_QUANTITY_TYPE,
              JNXEQUITIES_PTS_ITCH_QUANTITY_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_QUANTITY_MASK,
              JNXEQUITIES_PTS_ITCH_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_reject_reason_code,
            { JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_NAME,
              JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_FILTER,
              JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_TYPE,
              JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_DISPLAY,
              VALS(jnxequities_pts_itch_reject_reason_code_vals),
              JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_MASK,
              JNXEQUITIES_PTS_ITCH_REJECT_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_requested_sequence_number,
            { JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_requested_session,
            { JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_NAME,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_FILTER,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_TYPE,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_MASK,
              JNXEQUITIES_PTS_ITCH_REQUESTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_round_lot_size,
            { JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_NAME,
              JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_FILTER,
              JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_TYPE,
              JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_MASK,
              JNXEQUITIES_PTS_ITCH_ROUND_LOT_SIZE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_seconds,
            { JNXEQUITIES_PTS_ITCH_SECONDS_NAME,
              JNXEQUITIES_PTS_ITCH_SECONDS_FILTER,
              JNXEQUITIES_PTS_ITCH_SECONDS_TYPE,
              JNXEQUITIES_PTS_ITCH_SECONDS_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_SECONDS_MASK,
              JNXEQUITIES_PTS_ITCH_SECONDS_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_sequence_number,
            { JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_NAME,
              JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_FILTER,
              JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_TYPE,
              JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_MASK,
              JNXEQUITIES_PTS_ITCH_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_sequenced_message_type,
            { JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_DISPLAY,
              VALS(jnxequities_pts_itch_sequenced_message_type_vals),
              JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_SEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_server_packet_type,
            { JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DISPLAY,
              VALS(jnxequities_pts_itch_server_packet_type_vals),
              JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_SERVER_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_session,
            { JNXEQUITIES_PTS_ITCH_SESSION_NAME,
              JNXEQUITIES_PTS_ITCH_SESSION_FILTER,
              JNXEQUITIES_PTS_ITCH_SESSION_TYPE,
              JNXEQUITIES_PTS_ITCH_SESSION_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_SESSION_MASK,
              JNXEQUITIES_PTS_ITCH_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_short_selling_state,
            { JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_NAME,
              JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_FILTER,
              JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_TYPE,
              JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_DISPLAY,
              VALS(jnxequities_pts_itch_short_selling_state_vals),
              JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_MASK,
              JNXEQUITIES_PTS_ITCH_SHORT_SELLING_STATE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_system_event,
            { JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_NAME,
              JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_FILTER,
              JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_TYPE,
              JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_DISPLAY,
              VALS(jnxequities_pts_itch_system_event_vals),
              JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_MASK,
              JNXEQUITIES_PTS_ITCH_SYSTEM_EVENT_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_trading_state,
            { JNXEQUITIES_PTS_ITCH_TRADING_STATE_NAME,
              JNXEQUITIES_PTS_ITCH_TRADING_STATE_FILTER,
              JNXEQUITIES_PTS_ITCH_TRADING_STATE_TYPE,
              JNXEQUITIES_PTS_ITCH_TRADING_STATE_DISPLAY,
              VALS(jnxequities_pts_itch_trading_state_vals),
              JNXEQUITIES_PTS_ITCH_TRADING_STATE_MASK,
              JNXEQUITIES_PTS_ITCH_TRADING_STATE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_unsequenced_message,
            { JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_NAME,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_FILTER,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_MASK,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_unsequenced_message_type,
            { JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_NAME,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_FILTER,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_TYPE,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_MASK,
              JNXEQUITIES_PTS_ITCH_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_upper_price_limit,
            { JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_NAME,
              JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_FILTER,
              JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_TYPE,
              JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_DISPLAY,
              CF_FUNC(jnxequities_pts_itch_format_decimal_1_32_unsigned),
              JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_MASK,
              JNXEQUITIES_PTS_ITCH_UPPER_PRICE_LIMIT_DESCRIPTION,
              HFILL } },
        { &hf_jnxequities_pts_itch_username,
            { JNXEQUITIES_PTS_ITCH_USERNAME_NAME,
              JNXEQUITIES_PTS_ITCH_USERNAME_FILTER,
              JNXEQUITIES_PTS_ITCH_USERNAME_TYPE,
              JNXEQUITIES_PTS_ITCH_USERNAME_DISPLAY,
              NULL,
              JNXEQUITIES_PTS_ITCH_USERNAME_MASK,
              JNXEQUITIES_PTS_ITCH_USERNAME_DESCRIPTION,
              HFILL } },

        /* Generated */
        { &hf_jnxequities_pts_itch_time_of_day,
            { JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_NAME,
              JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_FILTER,
              FT_RELATIVE_TIME,
              BASE_NONE,
              NULL,
              0x0,
              JNXEQUITIES_PTS_ITCH_TIME_OF_DAY_DESCRIPTION,
              HFILL } },

        { &hf_jnxequities_pts_itch_utc,
            { JNXEQUITIES_PTS_ITCH_UTC_NAME,
              JNXEQUITIES_PTS_ITCH_UTC_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_UTC,
              NULL,
              0x0,
              JNXEQUITIES_PTS_ITCH_UTC_DESCRIPTION,
              HFILL } },

        { &hf_jnxequities_pts_itch_local,
            { JNXEQUITIES_PTS_ITCH_LOCAL_NAME,
              JNXEQUITIES_PTS_ITCH_LOCAL_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_LOCAL,
              NULL,
              0x0,
              JNXEQUITIES_PTS_ITCH_LOCAL_DESCRIPTION,
              HFILL } },

        { &hf_jnxequities_pts_itch_elapsed_nanoseconds,
            { JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_NAME,
              JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              JNXEQUITIES_PTS_ITCH_ELAPSED_NANOSECONDS_DESCRIPTION,
              HFILL } },

        { &hf_jnxequities_pts_itch_elapsed_seconds,
            { JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_NAME,
              JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              JNXEQUITIES_PTS_ITCH_ELAPSED_SECONDS_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_jnxequities_pts_itch,
        &ett_jnxequities_pts_itch_header,
        &ett_jnxequities_pts_itch_message,
        &ett_jnxequities_pts_itch_timestamp,
        &ett_jnxequities_pts_itch_client_packet_header,
        &ett_jnxequities_pts_itch_server_packet_header,
        &ett_jnxequities_pts_itch_message_header,
    };

    static ei_register_info ei[] = {
        { &ei_jnxequities_pts_itch_length,
            { JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_FILTER,
              JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_GROUP,
              JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_SEVERITY,
              JNXEQUITIES_PTS_ITCH_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_jnxequities_pts_itch = proto_register_protocol(JNXEQUITIES_PTS_ITCH_PROTOCOL_NAME, JNXEQUITIES_PTS_ITCH_PROTOCOL_SHORT, JNXEQUITIES_PTS_ITCH_PROTOCOL_FILTER);

    proto_register_field_array(proto_jnxequities_pts_itch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_jnxequities_pts_itch = expert_register_protocol(proto_jnxequities_pts_itch);
    expert_register_field_array(expert_jnxequities_pts_itch, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_jnxequities_pts_itch, NULL);

    prefs_register_enum_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_VERSION_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_version,
        jnxequities_pts_itch_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_show_headers);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_show_session_messages);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_show_application_messages);

    prefs_register_uint_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &jnxequities_pts_itch_pref_decimal_places);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_READ_NANOSECONDS_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_read_nanoseconds);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_READ_SECONDS_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_read_seconds);

    prefs_register_enum_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_ASSUME_ROLE_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_assume_role,
        jnxequities_pts_itch_assume_role_vals,
        false);

    prefs_register_uint_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION,
        10,
        &jnxequities_pts_itch_pref_acceptor_port);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_SWAP_SIDES_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_swap_sides);

    prefs_register_bool_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_INDEXES_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_show_indexes);

    range_convert_str(
        wmem_epan_scope(),
        &jnxequities_pts_itch_pref_ports,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_DEFAULT,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_NAME,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_TITLE,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_DESCRIPTION,
        &jnxequities_pts_itch_pref_ports,
        JNXEQUITIES_PTS_ITCH_PORTS_PREFERENCE_MAXIMUM);

    jnxequities_pts_itch_handle = register_dissector(JNXEQUITIES_PTS_ITCH_PROTOCOL_FILTER, dissect_jnxequities_pts_itch, proto_jnxequities_pts_itch);
}

void
proto_reg_handoff_jnxequities_pts_itch(void)
{
    heur_dissector_add("tcp", dissect_jnxequities_pts_itch_tcp_heur, "Jnx Pts Itch over TCP",
        "jnxequities_pts_itch_tcp", proto_jnxequities_pts_itch, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_jnxequities_pts_itch_udp_heur, "Jnx Pts Itch over UDP",
        "jnxequities_pts_itch_udp", proto_jnxequities_pts_itch, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", jnxequities_pts_itch_handle);
    dissector_add_for_decode_as("udp.port", jnxequities_pts_itch_handle);
}
