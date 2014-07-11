/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author David DIALLO <diallo@et.esiea.fr>
 *
 * Implements timeout keyword
 *
 */

#include "suricata-common.h"

#include "conf.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-timeout.h"

#include "queue.h"

#include "tm-threads.h"

#include "util-debug.h"
#include "util-privs.h"
#include "util-signal.h"

/* Time interval in second at which the thread o/p the timeout */
#define DETECT_TIMEOUT_TTS  8

#define DETECT_TIMEOUT_USECOND  (1)
#define DETECT_TIMEOUT_MSECOND  (1000 * DETECT_TIMEOUT_USECOND)
#define DETECT_TIMEOUT_SECOND   (1000 * DETECT_TIMEOUT_MSECOND)

#define DETECT_TIMEOUT_MAX      (60 * DETECT_TIMEOUT_SECOND)

typedef struct DetectTimeoutPacket_ {
    struct timeval tp;  /* Packet timestamp. */

    uint32_t    max, threshold;
    uint8_t     flags;

    TAILQ_ENTRY(DetectTimeoutPacket_) next;
} DetectTimeoutPacket;

#define DETECT_TIMEOUT_PACKET_ENABLE    (1<<0)
#define DETECT_TIMEOUT_PACKET_ALARM     (1<<1)

struct DetectTimeoutContext_ {
    struct timeval tc;  /* Control timestamp. */

    uint8_t flags;

    TAILQ_HEAD(, DetectTimeoutPacket_) packet_list;
} ctx;

#define DETECT_TIMEOUT_CONTEXT_ENABLE   (1<<0)

/**
 * \brief Regex for parsing the timeout string
 */
#define PARSE_REGEX     "^\\s*\"?\\s*([0-9]+)(us|ms|s)\\s*\"?\\s*$"
static pcre         *parse_regex;
static pcre_extra   *parse_regex_study;

#define MAX_SUBSTRINGS 30

void DetectTimeoutRegisterTests(void);

/*
 * \brief Packet match with signature condition(s), store timestamp and
 *             compute the time difference with previous packet
 */
int DetectTimeoutMatch(ThreadVars               *t,
                       DetectEngineThreadCtx    *det_ctx,
                       Packet                   *p,
                       Signature                *s,
                       SigMatch                 *sm)
{
    SCEnter();
    DetectTimeoutPacket *packet = (DetectTimeoutPacket *) sm->ctx;

    double diff_t;

    uint32_t diff;

    if (packet == NULL)
        SCReturn(0);

    if (packet->flags & DETECT_TIMEOUT_PACKET_ENABLE) {
        // Compute time difference between previous packet and previous Timeout thread wake-up
        diff_t = difftime(packet->tp.tv_sec, ctx.tc.tv_sec);

        // Compute time difference between the current and the previous packet
        diff = (uint32_t) difftime(p->ts.tv_sec, packet->tp.tv_sec) * DETECT_TIMEOUT_SECOND;
        diff += (p->ts.tv_usec - packet->tp.tv_usec);

        // Check and store the highest time difference
        if ((diff_t > 0)                                                 ||
            ((diff_t == 0) && (packet->tp.tv_usec > ctx.tc.tv_usec))     ||
            ((diff_t < 0) && (diff > packet->max))                        )
            packet->max = diff;
    } else {
        // Enable Data Timeout context
        packet->flags |= DETECT_TIMEOUT_PACKET_ENABLE;
    }

    // Store the current packet time
    packet->tp.tv_sec     = p->ts.tv_sec;
    packet->tp.tv_usec    = p->ts.tv_usec;

    SCReturn(0);
}

/** \internal
 *
 * \brief this function will free memory associated with DetectTimeoutData
 *
 * \param ptr    Pointer to DetectTimeoutData structure
 */
void DetectTimeoutFree(void *ptr) {
    SCEnter();
    DetectTimeoutPacket *packet = (DetectTimeoutPacket *) ptr;

    if (packet == NULL)
        return;

    TAILQ_REMOVE(&ctx.packet_list, packet, next);
    SCFree(packet);
    SCReturn;
}

/**
}
 * \brief     DetectTimeout thread.
 *             This thread wakes up every DETECT_TIMEOUT_TTS (time to sleep) seconds
 *
 * \param     arg
 *
 * \retval     NULL This is the value that is always returned
 */
static void *DetectTimeoutThread(void *arg)
{
    DetectTimeoutPacket *packet;
    ThreadVars          *tv = (ThreadVars *) arg;

    struct timeval now;

    double diff_t;

    uint32_t    diff;
    uint8_t     run = 1;

    // block usr2.  usr2 to be handled by the main thread only
    UtilSignalBlock(SIGUSR2);

    // Set the thread name
    if (SCSetThreadName(tv->name) < 0) {
        SCLogWarning(SC_ERR_THREAD_INIT, "Unable to set thread name");
    }

    if (tv->thread_setup_flags != 0)
        TmThreadSetupOptions(tv);

    // Set the threads capability
    tv->cap_flags = 0;

    SCDropCaps(tv);

    TmThreadsSetFlag(tv, THV_INIT_DONE);
    while (run) {
        if (TmThreadsCheckFlag(tv, THV_PAUSE)) {
            TmThreadsSetFlag(tv, THV_PAUSED);
            TmThreadTestThreadUnPaused(tv);
            TmThreadsUnsetFlag(tv, THV_PAUSED);
        }

        sleep(DETECT_TIMEOUT_TTS);

        // Get the current time
        memset(&now, 0, sizeof(now));
        TimeGet(&now);

        TAILQ_FOREACH(packet, &ctx.packet_list, next) {
            if (!(packet->flags & DETECT_TIMEOUT_PACKET_ENABLE))
                continue;

            // Compute time difference between previous packet and previous Timeout thread wake-up
            diff_t = difftime(ctx.tc.tv_sec, packet->tp.tv_sec);

            if ((diff_t > 0) || ((diff_t == 0) && (ctx.tc.tv_usec > packet->tp.tv_usec))) {
                // Compute time difference between previous wake-up and the previous received packet
                diff = (uint32_t) difftime(now.tv_sec, packet->tp.tv_sec) * DETECT_TIMEOUT_SECOND;
                diff += (now.tv_usec - packet->tp.tv_usec);

                if (diff > packet->threshold) {
                    if (!(packet->flags & DETECT_TIMEOUT_PACKET_ALARM)) {
                        SCLogWarning(SC_OK, "Alert Timeout");
                        packet->flags |= DETECT_TIMEOUT_PACKET_ALARM;
                    }
                }
            } else {
                if (packet->max > packet->threshold) {
                    SCLogWarning(SC_OK, "Alert Timeout");
                    packet->flags |= DETECT_TIMEOUT_PACKET_ALARM;
                } else {
                    packet->flags &= ~DETECT_TIMEOUT_PACKET_ALARM;
                }
            }
        }

        // Update Timeout thread timers
        ctx.tc.tv_sec   = now.tv_sec;
        ctx.tc.tv_usec  = now.tv_usec;

        if (TmThreadsCheckFlag(tv, THV_KILL))
            run = 0;
    }

    TmThreadsSetFlag(tv, THV_RUNNING_DONE);
    TmThreadWaitForFlag(tv, THV_DEINIT);
    TmThreadsSetFlag(tv, THV_CLOSED);

    return NULL;
}

/**
 * \brief Initialize DetectTimeout thread
 */
void DetectTimeoutInitThread(void)
{
    SCEnter();
    ThreadVars *tv = NULL;

    // Create Detect timeout thread
    tv = TmThreadCreateMgmtThread("DetectTimeoutThread", DetectTimeoutThread, 0);
    if (tv == NULL) {
        SCLogError(SC_ERR_THREAD_CREATE, "TmThreadCreateMgmtThread " "failed");
        exit(EXIT_FAILURE);
    }

    // Spawn thread
    if (TmThreadSpawn(tv) != 0) {
        SCLogError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed for " "DetectTimeoutThread");
        exit(EXIT_FAILURE);
    }

    // Set Timeout thread priority as High
    TmThreadSetThreadPriority(tv, PRIO_HIGH);

    SCReturn;
}

/** \internal
 *
 * \brief this function is used to add the parsed "id" option into the current signature
 *
 * \param de_ctx    Pointer to the Detection Engine Context
 * \param s         Pointer to the current Signature
 * \param str        Pointer to the user provided "id" option
 *
 * \retval 0 on Success or -1 on Failure
 */
static int DetectTimeoutSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    DetectTimeoutPacket    *packet;
    SigMatch             *sm = NULL;

    char     arg[MAX_SUBSTRINGS], unit[3];
    int        ret = 0, res = 0, ov[MAX_SUBSTRINGS];

    uint32_t threshold;

    ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0, ov, sizeof(ov));
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_PARSE, "timeout option pcre parse error: \"%s\"", str);
        goto error;
    }

    res = pcre_copy_substring((char *)str, ov, MAX_SUBSTRINGS, 2, unit, sizeof(unit));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    res = pcre_copy_substring((char *)str, ov, MAX_SUBSTRINGS, 1, arg, sizeof(arg));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    // Extract threshold value
    threshold = atoi((const char*) arg);

    // Convert threshold value according to its unit
    if (strncmp(unit,"s",1) == 0) {
        if (threshold > DETECT_TIMEOUT_MAX) {
            SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: timeout value \"%d\"s is not supported.", threshold);
            goto error;
        }

        threshold *= DETECT_TIMEOUT_SECOND;
    } else if (strncmp(unit,"ms",2) == 0) {
        threshold *= DETECT_TIMEOUT_MSECOND;
    } else if (strncmp(unit,"us",2) == 0) {
        threshold *= DETECT_TIMEOUT_USECOND;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: timeout unit \"%s\" is not supported.", unit);
        goto error;
    }

    // Initialize a Data Timeout structure and insert it to Data list
    packet = (DetectTimeoutPacket *) SCCalloc(1, sizeof(DetectTimeoutPacket));
    if (packet == NULL)
        goto error;
    packet->threshold = threshold;

    TAILQ_INSERT_TAIL(&ctx.packet_list, packet, next);

    // Initialize Timeout thread if it has not already done
    if (!(ctx.flags & DETECT_TIMEOUT_CONTEXT_ENABLE)) {
        DetectTimeoutInitThread();
        ctx.flags |= DETECT_TIMEOUT_CONTEXT_ENABLE;
    }

    // Okay so far so good, lets get this into a SigMatch and put it in the Signature.
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_TIMEOUT;
    sm->ctx = (void *) packet;

    // Do not generate any alert
    s->flags |= SIG_FLAG_NOALERT;

    /* modifiers, only run when entire sig has matched */
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);

    SCReturn(0);
error:
    if (packet != NULL)
        SCFree(packet);
    if (sm != NULL)
        SCFree(sm);
    SCReturn(1);
}

/**
 * \brief Registration function for timeout keyword
 */
void DetectTimeoutRegister (void) {
    SCEnter();
    const char *eb;
    int eo, opts = 0;

    sigmatch_table[DETECT_TIMEOUT].name             = "timeout";
    sigmatch_table[DETECT_TIMEOUT].desc             = "operate on timeout flag";
    sigmatch_table[DETECT_TIMEOUT].Match             = DetectTimeoutMatch;
    sigmatch_table[DETECT_TIMEOUT].Setup             = DetectTimeoutSetup;
    sigmatch_table[DETECT_TIMEOUT].Free              = DetectTimeoutFree;
    sigmatch_table[DETECT_TIMEOUT].RegisterTests     = DetectTimeoutRegisterTests;

    // Initialize Timeout context
    memset(&ctx, 0, sizeof(ctx));
    TAILQ_INIT(&ctx.packet_list);

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    SCReturn;
}

/**
 * \brief this function registers unit tests for DetectTimeout
 */
void DetectTimeoutRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
#endif /* UNITTESTS */
}
