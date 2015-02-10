// Copyright (C) 2012  JINMEI Tatuya
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
// REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
// INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
// LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
// OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
// PERFORMANCE OF THIS SOFTWARE.

#include <dispatcher.h>

#include <dns/rcode.h>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/shared_ptr.hpp>

#include <cassert>
#include <cstring>
#include <sstream>
#include <iostream>
#include <vector>
#include <stdexcept>

#include <netinet/in.h>

#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>

using namespace Queryperf;
using namespace isc::dns;
using namespace boost::posix_time;
using boost::lexical_cast;
using boost::shared_ptr;

namespace {
struct QueryStatistics {
    QueryStatistics(size_t nbuckets, size_t time)
        : queries_sent(0), queries_completed(0)
    {
        assert(0 < time);
        memset(rcodes, 0, sizeof(rcodes));
        memset(latency, 0, sizeof(latency));
        histogram_nbuckets = nbuckets;
        histogram_time = time;
        histogram_bps = (double) histogram_nbuckets / histogram_time;
        for (size_t i = 0; i <= histogram_nbuckets; ++i)
        {
            struct histogram_bucket* bucket = new struct histogram_bucket;
            memset(bucket, 0, sizeof(struct histogram_bucket));
            histogram_buckets.push_back(bucket);
        }
    }

    size_t queries_sent;
    size_t queries_completed;
    size_t rcodes[Dispatcher::MAX_RCODE];
    size_t histogram_nbuckets;
    size_t histogram_time;
    double histogram_bps;
    std::vector<struct histogram_bucket*> histogram_buckets;
    double latency[LT_MAX];
    std::vector<double> qps_results; // a list of QPS per worker thread
};

double
accumulateResult(const Dispatcher& disp, QueryStatistics& result) {
    result.queries_sent += disp.getQueriesSent();
    result.queries_completed += disp.getQueriesCompleted();
    for (uint16_t i = 0; i < Dispatcher::MAX_RCODE; ++i)
    {
        result.rcodes[i] += disp.getRcodes()[i];
    }

    result.latency[LT_SUM] += disp.getSumLatency();
    if (result.latency[LT_FASTEST] > disp.getFastestLatency())
    {
        result.latency[LT_FASTEST] = disp.getFastestLatency();
    }
    if (result.latency[LT_SLOWEST] < disp.getSlowestLatency())
    {
        result.latency[LT_SLOWEST] = disp.getSlowestLatency();
    }

    for (size_t i = 0; i <= result.histogram_nbuckets; ++i)
    {
        for (size_t k = 0; k < CATEGORY_MAX; ++k)
        {
            result.histogram_buckets[i]->categories[k] += disp.getBuckets()[i]->categories[k];
        }
    }

    const time_duration duration = disp.getEndTime() - disp.getStartTime();
    return (disp.getQueriesCompleted() / (
                static_cast<double>(duration.total_microseconds()) / 1000000));
}

// Default Parameters
uint16_t getDefaultPort() { return (Dispatcher::DEFAULT_PORT); }
long getDefaultDuration() { return (Dispatcher::DEFAULT_DURATION); }
const size_t DEFAULT_THREAD_COUNT = 1;
const char* const DEFAULT_CLASS = "IN";
const bool DEFAULT_DNSSEC = true; // set EDNS DO bit by default
const bool DEFAULT_EDNS = true; // set EDNS0 OPT RR by default
const char* const DEFAULT_DATA_FILE = "-"; // stdin
const char* const DEFAULT_PROTOCOL = "udp";
const size_t DEFAULT_BUCKETS = 200;
const size_t DEFAULT_HISTOGRAM_TIME = 1;

void
usage() {
    const std::string usage_head = "Usage: queryperf++ ";
    const std::string indent(usage_head.size(), ' ');
    std::cerr << usage_head
         << "[-C qclass] [-d datafile] [-D on|off] [-e on|off] [-A] [-l limit]\n";
    std::cerr << indent
         << "[-L] [-n #threads] [-p port] [-P udp|tcp] [-q query_sequence]\n";
    std::cerr << indent
         << "[-s server_addr] [-c] [-H histogram_buckets] [-T histogram_seconds]\n";
    std::cerr << "  -C sets default query class (default: "
         << DEFAULT_CLASS << ")\n";
    std::cerr << "  -d sets the input data file (default: stdin)\n";
    std::cerr << "  -D sets whether to set DNSSEC DO bit (default: "
         << (DEFAULT_DNSSEC ? "on" : "off") << ")\n";
    std::cerr << "  -e sets whether to enable EDNS (default: "
         << (DEFAULT_EDNS ? "on" : "off") << ")\n";
    std::cerr << "  -A print command-line arguments (default: disabled)\n";
    std::cerr << "  -l sets how long to run tests in seconds (default: "
         << getDefaultDuration() << ")\n";
    std::cerr << "  -L enables query preloading (default: disabled)\n";
    std::cerr << "  -n sets the number of querying threads (default: "
         << DEFAULT_THREAD_COUNT << ")\n";
    std::cerr << "  -p sets the port on which to query the server (default: "
         << getDefaultPort() << ")\n";
    std::cerr << "  -P sets transport protocol for queries (default: "
         << DEFAULT_PROTOCOL << ")\n";
    std::cerr << "  -q sets newline-separated query data (default: unspecified)\n";
    std::cerr << "  -Q sets the number of queries per second (default: unlimited)\n";
    std::cerr << "  -s sets the server to query (default: "
              << Dispatcher::DEFAULT_SERVER << ")\n";
    std::cerr << "  -c count rcode of each response (default: disabled)\n";
    std::cerr << "  -H print response latency histogram with these buckets (default: "
              << DEFAULT_BUCKETS << ")\n";
    std::cerr << "  -T print latency histogram equal and less than these seconds (use with -H) (default: "
              << DEFAULT_HISTOGRAM_TIME << "s)\n";
    std::cerr << std::endl;
    exit(1);
}

void*
runQueryperf(void* arg) {
    Dispatcher* disp = static_cast<Dispatcher*>(arg);
    try {
        disp->run();
    } catch (const std::exception& ex) {
        std::cerr << "Worker thread died unexpectedly: " << ex.what()
                  << std::endl;
    }
    return (NULL);
}

typedef shared_ptr<Dispatcher> DispatcherPtr;
typedef shared_ptr<std::stringstream> SStreamPtr;

bool
parseOnOffFlag(const char* optname, const char* const optarg,
               bool default_val)
{
    if (optarg != NULL) {
        if (std::string(optarg) == "on") {
            return (true);
        } else if (std::string(optarg) == "off") {
            return (false);
        } else {
            std::cerr << "Option argument of "<< optname
                      << " must be 'on' or 'off'" << std::endl;
            exit(1);
        }
    }
    return (default_val);
}

void
print_bucket(struct histogram_bucket *thisbucket, int maxval, const char *op,
             double time, size_t  histogram_nbuckets)
{
    int k;

    printf("%s%8.*fs", op, (int)log10(histogram_nbuckets), time);

    size_t total = 0;
    for (k = 0; k < CATEGORY_MAX; ++k)
    {
        total += thisbucket->categories[k];
    }

    for (k = 0; k < CATEGORY_MAX; k++) {
        printf("%9d ", thisbucket->categories[k]);
        if (0 != total)
        {
            printf("%2zu ", 100*thisbucket->categories[k]/total);
        }
        else
        {
            printf(" 0 ");
        }
    }
    printf("|");

    for (k = 0; k < CATEGORY_MAX; k++) {
        int hashes = (int) floor(60.0 * thisbucket->categories[k] / maxval);
        int j;

        for (j = 0; j < hashes; j++)
            putchar(category_markers[k]);
    }
    printf("\n");
}

void print_histogram(QueryStatistics &result)
{
    int maxval = 1;
    int i;

    if (result.histogram_nbuckets == 0)
        return;

    for (i = 0; i <= result.histogram_nbuckets; ++i)
    {
        size_t max_number = 0;
        for (size_t k = 0; k < CATEGORY_MAX; ++k)
        {
            max_number += result.histogram_buckets[i]->categories[k];
        }
        if (maxval < max_number)
        {
            maxval = max_number;
        }
    }
    
    printf("\nAverage latency: %f s\n", result.latency[LT_SUM] / result.queries_completed);

    printf("\nResponse latency distribution (total %zu responses):\n\n",
           result.queries_completed);

    printf("    Latency    Success  %%  Fail  %% |\n");

    for (i = 0; i <= result.histogram_nbuckets; i++) {
        const char* op = "< ";
        if (i == result.histogram_nbuckets)
        {
            op = ">=";
        }
        print_bucket(result.histogram_buckets[i], maxval, op,
                     (i + 1) / result.histogram_bps, result.histogram_nbuckets);

    }

    printf("\nLegend:\n\n");
    printf("##### = success responses (RCODE was NOERROR or NXDOMAIN)\n");
    printf("----- = failure responses (any other RCODE)\n");
}

}

int
main(int argc, char* argv[]) {
    bool count_rcode = false;
    bool print_args  = false;
    const char* qclass_txt = DEFAULT_CLASS;
    const char* data_file = NULL;
    const char* dnssec_flag_txt = NULL;
    const char* edns_flag_txt = NULL;
    const char* server_address = Dispatcher::DEFAULT_SERVER;
    const char* proto_txt = DEFAULT_PROTOCOL;
    std::string server_port_str = lexical_cast<std::string>(getDefaultPort());
    std::string time_limit_str =
        lexical_cast<std::string>(getDefaultDuration());
    const char* num_threads_txt = NULL;
    const char* histogram_nbuckets_txt = NULL;
    const char* histogram_time_txt = NULL;
    const char* query_txt = NULL;
    const char* qps_txt = NULL;
    size_t num_threads = DEFAULT_THREAD_COUNT;
    size_t histogram_nbuckets = DEFAULT_BUCKETS;
    size_t histogram_time = DEFAULT_HISTOGRAM_TIME;
    size_t qps = 0;
    bool preload = false;

    int ch;
    while ((ch = getopt(argc, argv, "C:d:D:Ae:hl:Ln:p:P:q:Q:s:cH:T:")) != -1) {
        switch (ch) {
        case 'C':
            qclass_txt = optarg;
            break;
        case 'd':
            data_file = optarg;
            break;
        case 'D':
            dnssec_flag_txt = optarg;
            break;
        case 'e':
            edns_flag_txt = optarg;
            break;
        case 'A':
            print_args = true;
            break;
        case 'n':
            num_threads_txt = optarg;
            break;
        case 's':
            server_address = optarg;
            break;
        case 'p':
            server_port_str = std::string(optarg);
            break;
        case 'P':
            proto_txt = optarg;
            break;
        case 'q':
            query_txt = optarg;
            break;
        case 'Q':
            qps_txt = optarg;
            break;
        case 'l':
            time_limit_str = std::string(optarg);
            break;
        case 'L':
            preload = true;
            break;
        case 'c':
            count_rcode = true;
            break;
        case 'H':
            histogram_nbuckets_txt = optarg;
            break;
        case 'T':
            histogram_time_txt = optarg;
            break;
        case 'h':
        case '?':
        default :
            usage();
        }
    }

    // Validation on options
    if (data_file == NULL && query_txt == NULL) {
        data_file = DEFAULT_DATA_FILE;
    }
    if (data_file != NULL && query_txt != NULL) {
        std::cerr << "-d and -Q cannot be specified at the same time"
                  << std::endl;
        return (1);
    }
    const bool dnssec_flag = parseOnOffFlag("-D", dnssec_flag_txt,
                                            DEFAULT_DNSSEC);
    const bool edns_flag = parseOnOffFlag("-e", edns_flag_txt, DEFAULT_EDNS);
    if (!edns_flag && dnssec_flag) {
        std::cerr << "[WARN] EDNS is disabled but DNSSEC is enabled; "
                  << "EDNS will still be included." << std::endl;
    }
    const std::string proto_str(proto_txt);
    if (proto_str != "udp" && proto_str != "tcp") {
        std::cerr << "Invalid protocol: " << proto_str << std::endl;
        return (1);
    }
    const int proto = proto_str == "udp" ? IPPROTO_UDP : IPPROTO_TCP;

    try {
        std::vector<DispatcherPtr> dispatchers;
        std::vector<SStreamPtr> input_streams;
        if (num_threads_txt != NULL) {
            num_threads = lexical_cast<size_t>(num_threads_txt);
        }
        if (num_threads > 1 && data_file != NULL &&
            std::string(data_file) == "-") {
            std::cerr << "stdin can be used as input only with 1 thread"
                      << std::endl;
            return (1);
        }

        if (NULL != histogram_nbuckets_txt)
        {
            histogram_nbuckets = lexical_cast<size_t>(histogram_nbuckets_txt);
        }
        if (NULL != histogram_time_txt)
        {
            histogram_time = lexical_cast<size_t>(histogram_time_txt);
            if (0 >= histogram_time)
            {
                std::cerr << "Must set seconds bigger than 0 for argument -T" << std::endl;
                exit(1);
            }
        }
        
        if (NULL != qps_txt)
        {
            qps = lexical_cast<size_t>(qps_txt);
        }

        // Prepare
        std::cout << "[Status] Processing input data" << std::endl;
        for (size_t i = 0; i < num_threads; ++i) {
            DispatcherPtr disp;
            if (data_file != NULL) {
                disp.reset(new Dispatcher(data_file));
            } else {
                assert(query_txt != NULL);
                SStreamPtr ss(new std::stringstream(query_txt));
                disp.reset(new Dispatcher(*ss));
                input_streams.push_back(ss);
            }
            disp->setServerAddress(server_address);
            disp->setServerPort(lexical_cast<uint16_t>(server_port_str));
            disp->setTestDuration(lexical_cast<size_t>(time_limit_str));
            disp->setDefaultQueryClass(qclass_txt);
            disp->setDNSSEC(dnssec_flag);
            disp->setEDNS(edns_flag);
            disp->setProtocol(proto);
            disp->setHistogramInput(histogram_nbuckets, histogram_time);
            disp->setQPS(qps/num_threads);
            // Preload must be the final step of configuration before running.
            if (preload) {
                disp->loadQueries();
            }
            dispatchers.push_back(disp);
        }

        // Run
        std::cout << "[Status] Sending queries to " << server_address
             << " over " << proto_str << ", port " << server_port_str << std::endl;
        std::vector<pthread_t> threads;
        const ptime start_time = microsec_clock::local_time();
        for (size_t i = 0; i < num_threads; ++i) {
            pthread_t th;
            const int error = pthread_create(&th, NULL, runQueryperf,
                                             dispatchers[i].get());
            if (error != 0) {
                throw std::runtime_error(
                    std::string("Failed to create a worker thread: ") +
                    strerror(error));
            }
            threads.push_back(th);
        }

        for (size_t i = 0; i < num_threads; ++i) {
            const int error = pthread_join(threads[i], NULL);
            if (error != 0) {
                // if join failed, we warn about it and just continue anyway
                std::cerr
                    << "pthread_join failed: " << strerror(error) << std::endl;
            }
        }
        const ptime end_time = microsec_clock::local_time();
        std::cout << "[Status] Testing complete" << std::endl;

        if (print_args)
        {
            std::cout << "[Status] Arguments: ";
            for (size_t i = 0; i < argc; ++i)
            {
                std::cout << argv[i] << " ";
            }
            std::cout << std::endl;
        }

        // Accumulate per-thread statistics.  Print the summary QPS for each,
        // and if more than one thread was used, print the sum of them.
        std::cout << "\nStatistics:\n\n";

        QueryStatistics result(histogram_nbuckets, histogram_time);
        double total_qps = 0;
        std::cout.precision(6);
        for (size_t i = 0; i < num_threads; ++i) {
            const double qps = accumulateResult(*dispatchers[i], result);
            total_qps += qps;
            std::cout << "  Queries per second #" << i <<
                ":  " << std::fixed << qps << " qps\n";
        }
        if (num_threads > 1) {
            std::cout << "         Summarized QPS:  " << std::fixed << total_qps
                 << " qps\n";
        }
        std::cout << std::endl;

        // Print the total result.
        std::cout << "  Queries sent:         " << result.queries_sent
             << " queries\n";
        std::cout << "  Queries completed:    " << result.queries_completed
             << " queries\n";
        std::cout << "\n";

        if (count_rcode)
        {
            for (uint16_t i = 0; i < Dispatcher::MAX_RCODE; ++i)
            {
                if (0 != result.rcodes[i])
                {
                    std::cout << "  Returned " << std::left << std::setw(10) << Rcode(i).toText()
                              << " : " << result.rcodes[i] << std::endl;
                }
            }
            std::cout << "\n";
        }
        
        std::cout << "  Percentage completed: " << std::setprecision(2);
        if (result.queries_sent > 0) {
            std::cout << std::setw(6)
                      << (static_cast<double>(result.queries_completed) /
                          result.queries_sent) * 100 << "%\n";
        } else {
            std::cout << "N/A\n";
        }
        std::cout << "  Percentage lost:      ";
        if (result.queries_sent > 0) {
            const size_t lost_count = result.queries_sent -
                result.queries_completed;
            std::cout << std::setw(6) << (static_cast<double>(lost_count) /
                                          result.queries_sent) * 100 << "%\n";
        } else {
            std::cout << "N/A\n";
        }
        std::cout << "\n";

        std::cout << "  Started at:           " << start_time << std::endl;
        std::cout << "  Finished at:          " << end_time << std::endl;
        const time_duration duration = end_time - start_time;
        std::cout
            << "  Run for:              " << std::setprecision(6)
            << (static_cast<double>(duration.total_microseconds()) / 1000000)
            << " seconds\n";
        std::cout << "\n";

        const double qps = result.queries_completed / (
            static_cast<double>(duration.total_microseconds()) / 1000000);
        std::cout.precision(6);
        std::cout << "  Queries per second:   " << std::fixed << qps
                  << " qps\n";
        std::cout << std::endl;
        print_histogram(result);
    } catch (const std::exception& ex) {
        std::cerr << "Unexpected failure: " << ex.what() << std::endl;
        return (1);
    }

    return (0);
}
