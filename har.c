#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ev.h>
#include <arpa/inet.h>
#include <ldns/ldns.h>
#include <curl/curl.h>
#include <confuse.h> /* config file parser */
#include <sys/select.h>
#include <search.h>
#include <ares.h>
#include <uriparser/Uri.h>
#include <sqlite3.h>
#include <math.h>

typedef struct DBStatements {
    sqlite3_stmt *name_configured;
    sqlite3_stmt *dns_success;
    sqlite3_stmt *dns_timeout;
    sqlite3_stmt *dns_error;
    sqlite3_stmt *insert_candidate;
    sqlite3_stmt *start_candidate_check;
    sqlite3_stmt *start_dns_query;
    sqlite3_stmt *init_check_name;
    sqlite3_stmt *init_check_candidate;
    sqlite3_stmt *response_success;
    sqlite3_stmt *response_timeout;
    sqlite3_stmt *connect_error;
    sqlite3_stmt *response_error;
    sqlite3_stmt *other_error;
    sqlite3_stmt *success_time;
    sqlite3_stmt *failure_time;
    sqlite3_stmt *response_stats;
    sqlite3_stmt *select_best_connect;
    sqlite3_stmt *select_best_response;
    sqlite3_stmt *select_group_connect;
    sqlite3_stmt *select_group_response;
    sqlite3_stmt *select_all_candidates;
} DBStatements;

typedef struct GlobalInfo {
    cfg_t *cfg;
    struct ev_loop *loop;
    CURLM *multi_h;
    ev_timer multi_timer;
    sqlite3 *db;
    DBStatements *stmt;
    ares_channel res_channel;
    struct ares_addr_node *res_addr_node;
    struct ev_io ares_io_watcher;
    struct ev_timer ares_timer;
    int ares_io_watcher_active;
    int ares_timer_active;
} GlobalInfo;

typedef struct CheckInfo {
    GlobalInfo *g;
    cfg_t *name_cfg;
    cfg_t *candidate_cfg;
    struct ev_timer timer;
} CheckInfo;

typedef struct CheckInstance {
    CheckInfo *c;
    void (*check_func)(struct CheckInstance *);
    char ip_address[INET6_ADDRSTRLEN];
    char *hostname;
    UriUriA uri;
    struct ev_timer curl_timer;
    struct curl_slist *slist;
    double response_time;
    double connect_time;
} CheckInstance;

typedef struct ProxyInfo {
    GlobalInfo *g;
    int fd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addrlen;
} ProxyInfo;

typedef struct SockInfo {
    GlobalInfo *g;
    struct ev_io watcher;
    int is_watching;
} SockInfo;

typedef struct GroupState {
    unsigned int num_candidates;
    unsigned int last_selection;
} GroupState;

static void 
prepare_sql(GlobalInfo *g)
{
    char *errmsg;
    if ((g->stmt = malloc(sizeof(DBStatements))) == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    if (sqlite3_open(cfg_getstr(g->cfg, "data_file"), &g->db) != SQLITE_OK) {
        fprintf(stderr, "Error opening data file '%s': %s\n",
                cfg_getstr(g->cfg, "data_file"),
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    /* We're willing to trade durability for performance */
    if (sqlite3_exec(g->db, "PRAGMA synchronous = OFF;", NULL, NULL, &errmsg) 
            != SQLITE_OK) {
        fprintf(stderr, "%s\n", errmsg);
        exit(EXIT_FAILURE);
    }
    if (sqlite3_exec(g->db,
            "CREATE TABLE IF NOT EXISTS names "
            "(name TEXT NOT NULL PRIMARY KEY, "
             "queries INT DEFAULT 0);",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating names table: %s\n", errmsg);
        exit(EXIT_FAILURE);
    }
    if (sqlite3_exec(g->db,
            "CREATE TABLE IF NOT EXISTS candidates "
            "(name TEXT NOT NULL, "
             "candidate_name TEXT NOT NULL, "
             "ip_address TEXT, "
             "chosen INT DEFAULT 0, "
             "dns_successes INT DEFAULT 0, "
             "dns_timeouts INT DEFAULT 0, "
             "dns_errors INT DEFAULT 0, "
             "last_dns_query_time REAL, "
             "last_dns_success_time REAL, "
             "last_dns_failure_time REAL, "
             "last_dns_status INTEGER, "
             "successes INT DEFAULT 0, "
             "timeouts INT DEFAULT 0, "
             "connect_errors INT DEFAULT 0, "
             "response_errors INT DEFAULT 0, "
             "other_errors INT DEFAULT 0, "
             "last_check_time REAL, "
             "last_success_time REAL, "
             "last_failure_time REAL, "
             "last_check_status INTEGER, "
             "connect_time REAL, "
             "response_time REAL, "
             "PRIMARY KEY (name, candidate_name));",
            NULL, NULL, &errmsg) != SQLITE_OK) {
        fprintf(stderr, "Error creating candidates table: %s\n", errmsg);
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, "SELECT 0 FROM names WHERE name = ?;",
                        -1, &g->stmt->name_configured, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, "UPDATE candidates "
                               "SET dns_successes = dns_successes + 1, "
                                    "last_dns_success_time = ?, "
                                    "last_dns_status = ? "
                               "WHERE name = ? AND candidate_name = ?;",
                        -1, &g->stmt->dns_success, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, "UPDATE candidates "
                               "SET dns_timeouts = dns_timeouts + 1, "
                                   "last_dns_failure_time = ?, "
                                   "last_dns_status = ? "
                               "WHERE name = ? AND candidate_name = ?;",
                        -1, &g->stmt->dns_timeout, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, "UPDATE candidates "
                               "SET dns_errors = dns_errors + 1, "
                                    "last_dns_failure_time = ?, "
                                    "last_dns_status = ? "
                               "WHERE name = ? AND candidate_name = ?;",
                        -1, &g->stmt->dns_error, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "INSERT OR IGNORE INTO candidates "
                        "(name, candidate_name) VALUES (?, ?);",
                        -1, &g->stmt->insert_candidate, NULL) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "UPDATE candidates "
                        "SET last_check_time = ?, "
                            "ip_address = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ?;",
                        -1, &g->stmt->start_candidate_check, NULL) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "UPDATE candidates "
                        "SET last_dns_query_time = ? "
                        "WHERE name = ? AND candidate_name = ?;",
                        -1, &g->stmt->start_dns_query, NULL) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "INSERT OR IGNORE INTO names (name) values (?);",
                        -1, &g->stmt->init_check_name, NULL) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "INSERT OR IGNORE INTO candidates "
                        "(name, candidate_name) VALUES (?, ?);",
                        -1, &g->stmt->init_check_candidate, NULL) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET successes = successes + 1, "
                            "last_check_status = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->response_success, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET timeouts = timeouts + 1, "
                            "last_check_status = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->response_timeout, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET connect_errors = connect_errors + 1, "
                            "last_check_status = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->connect_error, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET response_errors = response_errors + 1, "
                            "last_check_status = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->response_error, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET other_errors = other_errors + 1, "
                            "last_check_status = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->other_error, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET last_success_time = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->success_time, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "UPDATE candidates "
                        "SET last_failure_time = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->failure_time, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db, 
                        "UPDATE candidates "
                        "SET connect_time = ?, "
                            "response_time = ? "
                        "WHERE name = ? "
                        "AND candidate_name = ? "
                        "AND ip_address = ?;",
                        -1, &g->stmt->response_stats, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "SELECT ip_address, connect_time FROM candidates "
                        "WHERE name = ? "
                        "AND connect_time <= ? "
                        "AND (last_check_status = 200 "
                             "OR last_check_status = 0) "
                        "ORDER BY connect_time;",
                        -1, &g->stmt->select_best_connect, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "SELECT ip_address, response_time FROM candidates "
                        "WHERE name = ? "
                        "AND response_time <= ? "
                        "AND (last_check_status = 200 "
                             "OR last_check_status = 0) "
                        "ORDER BY response_time;",
                        -1, &g->stmt->select_best_response, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "SELECT ip_address FROM candidates "
                        "WHERE name = ? "
                        "AND connect_time <= ? "
                        "AND connect_time <= "
                             "(SELECT MIN(connect_time) + ? FROM candidates) "
                        "AND (last_check_status = 200 "
                             "OR last_check_status = 0) "
                        "ORDER BY ip_address;",
                        -1, &g->stmt->select_group_connect, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "SELECT ip_address FROM candidates "
                        "WHERE name = ? "
                        "AND response_time <= ? "
                        "AND response_time <= "
                             "(SELECT MIN(response_time) + ? FROM candidates) "
                        "AND (last_check_status = 200 "
                             "OR last_check_status = 0) "
                        "ORDER BY ip_address;",
                        -1, &g->stmt->select_group_response, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    if (sqlite3_prepare(g->db,
                        "SELECT ip_address FROM candidates "
                        "WHERE name = ?; ",
                        -1, &g->stmt->select_all_candidates, NULL) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
}

int
db_eval(sqlite3 *db,
        sqlite3_stmt *stmt)
{
    int ret;

    for (;;) {
        ret = sqlite3_step(stmt);
        switch (ret) {
            case SQLITE_ERROR:
            case SQLITE_MISUSE:
                fprintf(stderr, "Failed to execute statement: %s\n",
                        sqlite3_errmsg(db));
                exit(EXIT_FAILURE);
            case SQLITE_BUSY:
                sqlite3_reset(stmt);
                continue;
            case SQLITE_DONE:
                sqlite3_reset(stmt);
                return ret;
            case SQLITE_ROW:
                return ret;
        }
    }
}

void
free_check_instance(CheckInstance *inst)
{
    if (&inst->uri != NULL) { 
        uriFreeUriMembersA(&inst->uri);
    }
    free(inst->hostname);
    free(inst);
}

void
res_proxy_cb(void *arg,
             int status,
             int timeouts,
             unsigned char *abuf,
             int alen)
{
    ProxyInfo *p = (ProxyInfo *) arg;
    printf("res_proxy_cb called!\n");
    if (status == ARES_SUCCESS) {
        if (sendto(p->fd, abuf, alen, 0, 
                   (const struct sockaddr *) &p->peer_addr, 
                   p->peer_addrlen) == -1) {
            perror("sendto");
        }
    } else {
        fprintf(stderr, "Failed to proxy DNS query: %s\n", ares_strerror(status));
    }
    free(p);
}

void
add_all_ip(ldns_pkt *packet,
           const char *name,
           GlobalInfo *g)
{
    int i;

    ldns_rr_list *question = ldns_pkt_question(packet);
    ldns_rr_list *answer = ldns_pkt_answer(packet);
    ldns_rr *question_rr = ldns_rr_list_rr(question, 0);
    ldns_rdf *owner = ldns_rr_owner(question_rr);
    sqlite3_stmt *stmt = g->stmt->select_all_candidates;

    if (sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC) 
            != SQLITE_OK) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    for (i = 1; db_eval(g->db, stmt) == SQLITE_ROW; i++) {
        ldns_rdf *rd;
        ldns_rr *rr = ldns_rr_new();
        ldns_str2rdf_a(&rd, (const char *) sqlite3_column_text(stmt, 0));
        ldns_rr_push_rdf(rr, rd);
        ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
        ldns_rr_set_ttl(rr, 0);
        ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
        ldns_rr_list_push_rr(answer, rr);
        ldns_pkt_set_ancount(packet, i);
    }
    sqlite3_reset(stmt);
}


void
add_answer(ProxyInfo *p,
           ldns_pkt *packet)
{
    int i; 
    double max_rtt, group_rtt_threshold;
    sqlite3_stmt *stmt;
    ldns_rr *question_rr;
    ldns_rdf *owner;
    char *qname;
    const char *method = NULL;
    const char *rtt_mode = NULL;
    const char *failure_mode = NULL;
    ldns_rr_list *question = ldns_pkt_question(packet);
    ldns_rr_list *answer = ldns_pkt_answer(packet);
    cfg_t *name_cfg;

    if (ldns_rr_list_rr_count(question) == 0) {
        /* this shouldn't happen */
        return;
    }
    question_rr = ldns_rr_list_rr(question, 0);
    if (question_rr == NULL) {
        /* this shouldn't happen either */
        return;
    }
    owner = ldns_rr_owner(question_rr);
    qname = ldns_rdf2str(owner);
    qname[strlen(qname) - 1] = '\0'; /* trim trailing '.' */
    
    for (i = 0; i < cfg_size(p->g->cfg, "name"); i++) {
        const char *name;
        name_cfg = cfg_getnsec(p->g->cfg, "name", i);
        name = cfg_title(name_cfg);
        if (strncmp(qname, name, strlen(name)) == 0) {
            method = cfg_getstr(name_cfg, "selection_method");
            rtt_mode = cfg_getstr(name_cfg, "rtt_mode");
            failure_mode = cfg_getstr(name_cfg, "failure_mode");
            max_rtt = cfg_getfloat(name_cfg, "max_rtt");
            group_rtt_threshold = cfg_getfloat(name_cfg, "group_rtt_threshold");
            break;
        }
    }
    if (method == NULL || rtt_mode == NULL) {
        free(qname);
        return;
    }

    ldns_pkt_set_flags(packet, LDNS_AA|LDNS_QR|LDNS_RA);

    if (strncmp(method, "best_rtt", 7) == 0) {
        if (strncmp(rtt_mode, "total", 5) == 0) {
            stmt = p->g->stmt->select_best_response;
        } else {
            /* use connect time instead of response time */
            /* TODO: work with standard tcp connect() */
            stmt = p->g->stmt->select_best_connect;
        }
        if (   (sqlite3_bind_text(stmt, 1, qname, strlen(qname), SQLITE_STATIC) 
                != SQLITE_OK) 
            || (sqlite3_bind_double(stmt, 2, max_rtt) != SQLITE_OK)) {
            fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                    sqlite3_errmsg(p->g->db));
            exit(EXIT_FAILURE);
        }
        if (db_eval(p->g->db, stmt) == SQLITE_ROW) {
            /* TODO: handle AAAA responses */
            ldns_rdf *rd;
            ldns_rr *rr = ldns_rr_new();
            ldns_str2rdf_a(&rd, (const char *) sqlite3_column_text(stmt, 0));
            ldns_rr_push_rdf(rr, rd);
            ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
            ldns_rr_set_ttl(rr, 0);
            ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
            ldns_rr_list_push_rr(answer, rr);
            ldns_pkt_set_ancount(packet, 1);
        } else {
            /* no rows returned - failure */
            if (strncmp(failure_mode, "all", 3) == 0) {
                add_all_ip(packet, qname, p->g);
            }
        }
    } else if (strncmp(method, "group_rtt_rr", 12) == 0) {
        unsigned int nhosts = 0;
        struct candidate_info {
            char ip_address[INET6_ADDRSTRLEN];
            struct candidate_info *next;
        };
        struct candidate_info *head;
        struct candidate_info *next = NULL;
        struct candidate_info *cur = NULL;

        GroupState *group_state = 
            (GroupState *) name_cfg->opts->simple_value;

        if (strncmp(rtt_mode, "total", 5) == 0) {
            stmt = p->g->stmt->select_group_response;
        } else {
            /* use connect time instead of response time */
            stmt = p->g->stmt->select_group_connect;
        }
        if (   (sqlite3_bind_text(stmt, 1, qname, strlen(qname), SQLITE_STATIC) 
                != SQLITE_OK) 
            || (sqlite3_bind_double(stmt, 2, max_rtt) != SQLITE_OK)
            || (sqlite3_bind_double(stmt, 3, group_rtt_threshold) != SQLITE_OK)) {
            fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                    sqlite3_errmsg(p->g->db));
            exit(EXIT_FAILURE);
        }
        /* create a linked list of each IP address */
        for (i = 0; db_eval(p->g->db, stmt) == SQLITE_ROW; i++) {
            head = malloc(sizeof(struct candidate_info));
            strncpy(head->ip_address, 
                    (char *) sqlite3_column_text(stmt, 0),
                    INET6_ADDRSTRLEN);
            head->next = next;
            next = head;
            nhosts++;
        }
        if (nhosts) {
            if (nhosts == group_state->num_candidates) {
                /* number of viable hosts hasn't changed;
                 * increment the selection counter or roll it over */
                group_state->last_selection++;
                if (group_state->last_selection == nhosts) {
                    group_state->last_selection = 0;
                }
            } else {
                group_state->last_selection = 0;
            }
            /* last_selection is now the current selection; iterate through our
             * list to find the address we'll use */
            cur = head;
            for (i = 0; i < group_state->last_selection; i++) {
                cur = cur->next;
            }
            ldns_rdf *rd;
            ldns_rr *rr = ldns_rr_new();
            ldns_str2rdf_a(&rd, cur->ip_address);
            ldns_rr_push_rdf(rr, rd);
            ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
            ldns_rr_set_ttl(rr, 0);
            ldns_rr_set_type(rr, LDNS_RR_TYPE_A);
            ldns_rr_list_push_rr(answer, rr);
            ldns_pkt_set_ancount(packet, 1);
            /* free up everything */
            while (head != NULL) {
                cur = head;
                head = head->next;
                free(cur);
            }
        } else {
            /* no rows returned - failure */
            if (strncmp(failure_mode, "all", 3) == 0) {
                add_all_ip(packet, qname, p->g);
            }
        }
        group_state->num_candidates = nhosts;
    }
    sqlite3_reset(stmt);
    free(qname);
}

void
dns_lsock_cb(EV_P_ struct ev_io *w, 
             int revents) 
{
    char in[1024];
    uint8_t *out;
    ssize_t inlen;
    size_t outlen;
    ldns_pkt *packet;
    ldns_status status;

    GlobalInfo *g = w->data;
    ProxyInfo *p = malloc(sizeof(ProxyInfo));
    p->g = g;
    p->fd = w->fd;

    memset(in, 0, sizeof(in));
    memset(&p->peer_addr, 0, sizeof(p->peer_addr));
    p->peer_addrlen = sizeof(p->peer_addr);

    /* read data from socket */
    if ((inlen = recvfrom(w->fd, in, sizeof(in), 0, /*flags*/
                          (struct sockaddr *) &p->peer_addr, 
                          &p->peer_addrlen)) == -1) { 
        perror("recvfrom");
        exit(EXIT_FAILURE);
    } 

    /* parse data into DNS packet format */
    if ((status = ldns_wire2pkt(&packet, 
                                in, 
                                (size_t) inlen)) != LDNS_STATUS_OK) {
        fprintf(stderr, "Failed to read DNS packet: %s\n", 
                ldns_get_errorstr_by_id(status));
        ldns_pkt_free(packet);
        free(p);
        return;
    }

    add_answer(p, packet);

    if (ldns_rr_list_rr_count(ldns_pkt_answer(packet))) {
        /* we added an answer section */
        if ((status = ldns_pkt2wire(&out, (const ldns_pkt *) packet, &outlen))
                != LDNS_STATUS_OK) {
            fprintf(stderr, "Failed to build DNS packet: %s\n", 
                    ldns_get_errorstr_by_id(status));
            ldns_pkt_free(packet);
            free(p);
            return;
        }
        if (sendto(w->fd, out, outlen, 0, 
                   (const struct sockaddr *) &p->peer_addr, 
                   p->peer_addrlen) == -1) {
            perror("sendto");
        }
        free(out);
        free(p);
    } else {
        ares_send(g->res_channel, in, (int) inlen, res_proxy_cb, p);
    }
    ldns_pkt_free(packet);
}

void
init_dns_srv_watcher(GlobalInfo *g,
                     char *interface,
                     int port)
{
    char service[255];
    struct addrinfo hints, *addrinfo, *p;
    struct ev_loop *loop = g->loop;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    if (interface == NULL) {
        hints.ai_flags = AI_PASSIVE;
    }

    sprintf(service, "%d", port);
    if (getaddrinfo(interface, service, &hints, &addrinfo) != 0) {
        perror("getaddrinfo");
        exit(EXIT_FAILURE);
    }
    for (p = addrinfo; p != NULL; p = p->ai_next) {
        int fd;
        ev_io *w;
        int reuseaddr = 1;

        if ((fd = socket(p->ai_family, p->ai_socktype, 0)) == -1) {
            perror("socket");
            exit(EXIT_FAILURE);
        }
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                       &reuseaddr, sizeof(reuseaddr))) {
            perror("setsockopt");
            exit(EXIT_FAILURE);
        }
        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("bind");
            exit(EXIT_FAILURE);
        }
        w = malloc(sizeof(ev_io));
        memset(w, 0, sizeof(w));
        ev_io_init(w, dns_lsock_cb, fd, EV_READ);
        ev_io_start(EV_A_ w);
        w->data = g;
    }
    freeaddrinfo(addrinfo);
}

size_t
discard_data(void *data,
             size_t size,
             size_t nmemb,
             void *userdata)
{
    return (size * nmemb);
}

void
check_http(CheckInstance *inst)
{
    const char *src;
    char *dst, *effective_uri;
    size_t len;
    CheckInfo *c = inst->c;
    GlobalInfo *g = c->g;
    CURL *h = curl_easy_init();
    char *host_hdr = malloc(7 * sizeof(char) + strlen(inst->hostname));
   
    /* replace hostname in check URL with resolved IP address */
    len = inst->uri.hostText.first - inst->uri.scheme.first;
    for (src = inst->uri.hostText.afterLast; *src != '\0'; src++, len++);
    len += strlen(inst->ip_address);
    effective_uri = (char *) malloc((len + 1) * sizeof(char));
    memset(effective_uri, 0, (len + 1) * sizeof(char));
    for (src = inst->uri.scheme.first, dst = effective_uri;
         src < inst->uri.hostText.first;  
         *dst++ = *src++);
    for (src = inst->ip_address; *src != '\0'; *dst++ = *src++);
    for (src = inst->uri.hostText.afterLast; *src != '\0'; *dst++ = *src++);
    *dst = '\0';

    printf("translated address: %s (%d bytes)\n", effective_uri, (int) strlen(effective_uri));

    sprintf(host_hdr, "Host: %s", inst->hostname);
    inst->slist = NULL;
    inst->slist = curl_slist_append(inst->slist, host_hdr);

    curl_easy_setopt(h, CURLOPT_URL, effective_uri);
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, inst->slist);
    curl_easy_setopt(h, CURLOPT_VERBOSE, 1);
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, discard_data);
    curl_easy_setopt(h, CURLOPT_FORBID_REUSE, 1);
    curl_easy_setopt(h, CURLOPT_DNS_CACHE_TIMEOUT, 0);
    curl_easy_setopt(h, CURLOPT_TCP_NODELAY, 0);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, 
                     (long) (cfg_getfloat(inst->c->name_cfg, "check_frequency") * 1000));
    curl_easy_setopt(h, CURLOPT_PRIVATE, inst);
    curl_easy_setopt(h, CURLOPT_USERAGENT, "har/0.1");

    curl_multi_add_handle(g->multi_h, h);

    free(host_hdr);
    free(effective_uri);
}

void resolver_cb(void *arg,
                 int status,
                 int timeouts,
                 struct hostent *hostent)
{
    sqlite3_stmt *stmt;
    struct timeval tv;
    double now;
    CheckInstance *inst = (CheckInstance *) arg;
    CheckInfo *c = inst->c;
    GlobalInfo *g = c->g;

    const char *candidate = cfg_title(c->candidate_cfg);
    const char *name = cfg_title(c->name_cfg);

    gettimeofday(&tv, NULL);
    now = (double) tv.tv_sec + tv.tv_usec / 10e6;

    printf("resolver callback called\n");

    switch (status) {
        case ARES_SUCCESS:
            stmt = g->stmt->dns_success;
            break;
        case ARES_ETIMEOUT:
            stmt = g->stmt->dns_timeout;
            break;
        default:
            stmt = g->stmt->dns_error;
    }

    if (   (sqlite3_bind_double(stmt, 1, now) != SQLITE_OK)
        || (sqlite3_bind_int(stmt, 2, status) != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 3, name, strlen(name), SQLITE_STATIC) 
            != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 4, candidate, strlen(candidate), SQLITE_STATIC) 
            != SQLITE_OK)) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    if (status == ARES_SUCCESS) {
        inet_ntop(AF_INET, hostent->h_addr, inst->ip_address, INET6_ADDRSTRLEN);

        stmt = g->stmt->insert_candidate;
        if (   (sqlite3_bind_text(stmt, 1, 
                                  name, strlen(name), 
                                  SQLITE_STATIC) != SQLITE_OK) 
            || (sqlite3_bind_text(stmt, 2, 
                                  candidate, strlen(candidate), 
                                  SQLITE_STATIC) != SQLITE_OK)) {
            fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                    sqlite3_errmsg(g->db));
            exit(EXIT_FAILURE);
        }
        db_eval(g->db, stmt);

        stmt = g->stmt->start_candidate_check;
        if (   (sqlite3_bind_double(stmt, 1, now) != SQLITE_OK)
            || (sqlite3_bind_text(stmt, 2, inst->ip_address, strlen(inst->ip_address), SQLITE_STATIC) != SQLITE_OK)
            || (sqlite3_bind_text(stmt, 3, name, strlen(name), SQLITE_STATIC) != SQLITE_OK) 
            || (sqlite3_bind_text(stmt, 4, candidate, strlen(candidate), SQLITE_STATIC) != SQLITE_OK)) {
            fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                    sqlite3_errmsg(g->db));
            exit(EXIT_FAILURE);
        }
        db_eval(g->db, stmt);
        inst->check_func(inst);
    } else {
        /* Resolution failed */
        fprintf(stderr, "error resolving %s: %s\n",
                inst->hostname, ares_strerror(status));
        free_check_instance(inst);
    }
}

void 
handle_ares_io (EV_P_ struct ev_io *w,
                int revents)
{
    GlobalInfo *g = (GlobalInfo *) w->data;
    printf("handling ares %d request on fd %d\n", 
             revents,
             w->fd);
    ares_process_fd(g->res_channel, 
                    (revents & EV_READ) ? w->fd : ARES_SOCKET_BAD,
                    (revents & EV_WRITE) ? w->fd : ARES_SOCKET_BAD);
}

void
handle_ares_timeout (EV_P_ struct ev_timer *w,
                     int revents)
{
    struct timeval tv;
    struct timeval *timeout;
    GlobalInfo *g = (GlobalInfo *) w->data;

    printf("handling ares timeout\n");
    ares_process_fd(g->res_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    timeout = ares_timeout(g->res_channel, NULL, &tv);
    if (g->ares_timer_active) {
        ev_timer_stop(EV_A_ w);
        g->ares_timer_active = 0;
    }
    if (timeout == NULL) {
        printf("handle_ares_timeout: no timeout returned, stopping timer");
    } else {
        printf("handle_ares_timeout: setting up timeout of %.6f seconds\n",
                     (double) timeout->tv_sec + timeout->tv_usec / 1e6);
        ev_timer_set(w, (double) timeout->tv_sec + timeout->tv_usec / 1e6, 0.);
        ev_timer_start(EV_A_ w);
        g->ares_timer_active = 1;
    } 
}

void setup_ares_io_watcher(void *data,
                           int fd,
                           int read,
                           int write)
{
    GlobalInfo *g = (GlobalInfo *) data;
    struct ev_loop *loop = g->loop;
    struct timeval tv;
    struct timeval *timeout;

    int events = 0;
    if (read) {
        events |= EV_READ;
        printf("ares read watcher requested on fd %d\n", fd);
    }
    if (write) {
        events |= EV_WRITE;
        printf("ares write watcher requested on fd %d\n", fd);
    }
    if (events) {
        ev_io_init(&g->ares_io_watcher, handle_ares_io, fd, events);
        ev_io_start(EV_A_ &g->ares_io_watcher);
        g->ares_io_watcher.data = g;
        g->ares_io_watcher_active = 1;

    } else {
        /* tear down watchers */
        printf("ares requested watcher teardown on fd %d\n", fd);
        if (g->ares_io_watcher_active) {
            printf("watcher was active, initiating teardown on fd %d\n", fd);
            ev_io_stop(EV_A_ &g->ares_io_watcher);
            printf("teardown on fd %d completed\n", fd);
            g->ares_io_watcher_active = 0;
        }
    }
    timeout = ares_timeout(g->res_channel, NULL, &tv);
    if (g->ares_timer_active) {
        ev_timer_stop(EV_A_ &g->ares_timer);
        g->ares_timer_active = 0;
    }
    if (timeout == NULL) {
        printf("handle_ares_timeout: no timeout returned, stopping timer\n");
    } else {
        printf("handle_ares_timeout: setting up timeout of %.6f seconds\n",
                     (double) timeout->tv_sec + timeout->tv_usec / 1e6);
        ev_timer_set(&g->ares_timer, (double) timeout->tv_sec + timeout->tv_usec / 1e6, 0.);
        ev_timer_start(EV_A_ &g->ares_timer);
        g->ares_timer_active = 1;
    } 
}


void
test_candidate_http(EV_P_ struct ev_timer *w,
                    int revents) 
{
    UriParserStateA parser_state;
    struct timeval tv;
    struct timeval *timeout;
    double now;
    int hostlen;
    CheckInstance *inst;
    sqlite3_stmt *stmt;

    CheckInfo *c = w->data;
    GlobalInfo *g = c->g;

    const char *name = cfg_title(c->name_cfg);
    const char *candidate = cfg_title(c->candidate_cfg);
    const char *check_address = cfg_getstr(c->candidate_cfg, "check_address");

    inst = (CheckInstance *) malloc(sizeof(CheckInstance));
    inst->c = c;
    inst->check_func = check_http;
    printf("Testing candidate %s\n", candidate);

    parser_state.uri = &inst->uri;
    if (uriParseUriA(&parser_state, check_address) != URI_SUCCESS) {
        fprintf(stderr, "Failed to parse check_address '%s'\n", candidate);
        exit(EXIT_FAILURE);
    }
    hostlen = inst->uri.hostText.afterLast - inst->uri.hostText.first;
    inst->hostname = malloc(sizeof(char) * (hostlen + 1));
    memset(inst->hostname, 0, sizeof(char) * (hostlen + 1));
    strncpy(inst->hostname, inst->uri.hostText.first, hostlen);

    printf("hostname to resolve is %s\n", inst->hostname);

    gettimeofday(&tv, NULL);
    now = (double) tv.tv_sec + tv.tv_usec / 10e6;

    stmt = g->stmt->start_dns_query;
    if (   (sqlite3_bind_double(stmt, 1, now) != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 2, name, strlen(name), SQLITE_STATIC) != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 3, candidate, strlen(candidate), SQLITE_STATIC) != SQLITE_OK)) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    ares_gethostbyname(g->res_channel, inst->hostname, AF_INET, resolver_cb, inst);
    timeout = ares_timeout(g->res_channel, NULL, &tv);
    if (g->ares_timer_active) {
        ev_timer_stop(EV_A_ &g->ares_timer);
        g->ares_timer_active = 0;
    }
    if (timeout != NULL) {
        printf("test_candidate: setting up timeout of %.6f seconds\n",
                     (double) timeout->tv_sec + timeout->tv_usec / 1e6);
        ev_timer_init(&g->ares_timer, handle_ares_timeout,
                     (double) timeout->tv_sec + timeout->tv_usec / 1e6, 0.);
        ev_timer_start(EV_A_ &g->ares_timer);
        g->ares_timer.data = g;
        g->ares_timer_active = 1;
    }
}

void
init_check(CheckInfo *c) 
{
    double check_frequency;
    sqlite3_stmt *stmt;
    GlobalInfo *g = c->g;
    struct ev_loop *loop = g->loop;
    const char *name = cfg_title(c->name_cfg);
    const char *candidate = cfg_title(c->candidate_cfg);
    const char *check_method = cfg_getstr(c->name_cfg, "check_method");

    if ((check_frequency = cfg_getfloat(c->name_cfg, "check_frequency")) <= 0) {
        fprintf(stderr, "FATAL: check_frequency for name '%s' must be a positive number\n",
                name);
        exit(EXIT_FAILURE);
    }

    stmt = g->stmt->init_check_name;
    if (   (sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC) != SQLITE_OK)) { 
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    stmt = g->stmt->init_check_candidate;
    if (   (sqlite3_bind_text(stmt, 1, name, strlen(name), SQLITE_STATIC) != SQLITE_OK) 
        || (sqlite3_bind_text(stmt, 2, candidate, strlen(candidate), SQLITE_STATIC) != SQLITE_OK)) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    if (strncmp(check_method, "http", 4) == 0) {
        ev_timer_init(&c->timer, test_candidate_http, 0, check_frequency);
    } else {
        fprintf(stderr, "FATAL: Candidate '%s' for name '%s': unsupported check_method '%s'\n",
                        candidate, name, check_method);
        exit(EXIT_FAILURE);
    }
    ev_timer_start(EV_A_ &c->timer);
    c->timer.data = c;
}

static void
record_check_status(CheckInstance *inst, 
                    int check_status)
{
    sqlite3_stmt *stmt;
    struct timeval tv;
    double now;

    CheckInfo *c = inst->c;
    GlobalInfo *g = c->g;

    const char *candidate = cfg_title(c->candidate_cfg);
    const char *name = cfg_title(c->name_cfg);

    gettimeofday(&tv, NULL);
    now = (double) tv.tv_sec + tv.tv_usec / 10e6;

    if (check_status == 200) {
        stmt = g->stmt->response_success;
    } else if (check_status == CURLE_OPERATION_TIMEDOUT) {
        stmt = g->stmt->response_timeout;
    } else if (check_status == CURLE_COULDNT_CONNECT) {
        stmt = g->stmt->connect_error;
    } else {
        stmt = g->stmt->other_error;
    }

    if (   (sqlite3_bind_int(stmt, 1, check_status) != SQLITE_OK) 
        || (sqlite3_bind_text(stmt, 2, name, 
                              strlen(name), SQLITE_STATIC) != SQLITE_OK) 
        || (sqlite3_bind_text(stmt, 3, candidate, 
                              strlen(candidate), SQLITE_STATIC) != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 4, inst->ip_address, 
                              strlen(inst->ip_address), SQLITE_STATIC) != SQLITE_OK)) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    stmt = check_status == 200 ? g->stmt->success_time : g->stmt->failure_time;
    
    if (   (sqlite3_bind_double(stmt, 1, now) != SQLITE_OK) 
        || (sqlite3_bind_text(stmt, 2, name, 
                              strlen(name), SQLITE_STATIC) != SQLITE_OK) 
        || (sqlite3_bind_text(stmt, 3, candidate, 
                              strlen(candidate), SQLITE_STATIC) != SQLITE_OK)
        || (sqlite3_bind_text(stmt, 4, inst->ip_address, 
                              strlen(inst->ip_address), SQLITE_STATIC) != SQLITE_OK)) {
        fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                sqlite3_errmsg(g->db));
        exit(EXIT_FAILURE);
    }
    db_eval(g->db, stmt);

    if (check_status == 200) {
        stmt = g->stmt->response_stats;
        if (   (sqlite3_bind_double(stmt, 1, inst->connect_time) != SQLITE_OK) 
            || (sqlite3_bind_double(stmt, 2, inst->response_time) != SQLITE_OK) 
            || (sqlite3_bind_text(stmt, 3, name, 
                                  strlen(name), SQLITE_STATIC) != SQLITE_OK) 
            || (sqlite3_bind_text(stmt, 4, candidate, 
                                  strlen(candidate), SQLITE_STATIC) != SQLITE_OK)
            || (sqlite3_bind_text(stmt, 5, inst->ip_address, 
                                  strlen(inst->ip_address), SQLITE_STATIC) != SQLITE_OK)) {
            fprintf(stderr, "Failed to bind SQL parameters: %s\n",
                    sqlite3_errmsg(g->db));
            exit(EXIT_FAILURE);
        }
        db_eval(g->db, stmt);
    }
}


void
check_curl_multi(GlobalInfo *g)
{
    CURLMsg *msg;
    CURL *easy_h;
    CURLcode res;
    int msgs_left;
    CheckInstance *inst;
    long response_code;
    
    while ((msg = curl_multi_info_read(g->multi_h, &msgs_left)) != NULL) {
        if (msg->msg == CURLMSG_DONE) {
            easy_h = msg->easy_handle;
            res = msg->data.result;
            curl_easy_getinfo(easy_h, CURLINFO_PRIVATE, &inst);

            if (res == CURLE_OK) {
                curl_easy_getinfo(easy_h, CURLINFO_RESPONSE_CODE, &response_code);
                curl_easy_getinfo(easy_h, CURLINFO_TOTAL_TIME, &inst->response_time);
                curl_easy_getinfo(easy_h, CURLINFO_CONNECT_TIME, &inst->connect_time);
            } else {
                response_code = res;
                fprintf(stderr, "Error: %s\n", curl_easy_strerror(res));
            }
            record_check_status(inst, response_code);
            curl_multi_remove_handle(g->multi_h, easy_h);
            curl_easy_cleanup(easy_h);
            curl_slist_free_all(inst->slist);
            free_check_instance(inst);
        }
    }
}

void
handle_curl_timeout(EV_P_ struct ev_timer *w,
                    int revents) 
{
    int running_handles;
    CURLMcode rc; 

    GlobalInfo *g = (GlobalInfo *) w->data;
    rc = curl_multi_socket_action(g->multi_h, CURL_SOCKET_TIMEOUT, 0, &running_handles); 
    if (rc != CURLM_OK) {
        fprintf(stderr, "curl_handle_timeout(): %s\n", curl_multi_strerror(rc));
    }
    check_curl_multi(g);
}

void
handle_curl_io(EV_P_ struct ev_io *w,
               int revents)
{
    int ev_bitmask = 0; 
    int running_handles = 0;
 
    SockInfo *s = (SockInfo *) w->data;
    GlobalInfo *g = s->g;

    if (revents & EV_READ) {
        ev_bitmask |= CURL_CSELECT_IN;
    } 
    if (revents & EV_WRITE) {
        ev_bitmask |= CURL_CSELECT_OUT;
    }
    curl_multi_socket_action(g->multi_h, w->fd, ev_bitmask, &running_handles);
    check_curl_multi(g);
    if (running_handles == 0) {
        ev_timer_stop(EV_A_ &g->multi_timer);
    }
}

/* This function gets called when curl_multi wants us to schedule or
 * teardown a timer watcher */
int 
setup_curl_multi_timer(CURLM *multi_h,
                       long timeout_ms,
                       GlobalInfo *g)
{
    struct ev_loop *loop = g->loop;
    printf("entering %s\n", __func__);
    /* First, cancel the existing timer */
    ev_timer_stop(g->loop, &g->multi_timer);
    printf("stopping curl timer\n");
    if (timeout_ms > 0) {
        double t = timeout_ms / 1000;
        printf("starting curl timer for %ld ms\n", timeout_ms);
        ev_timer_init(&g->multi_timer, handle_curl_timeout, t, 0.);
        ev_timer_start(EV_A_ &g->multi_timer);
    } else {
        /* The pressure's on, no time to lose */
        printf("handling curl timeout now!  %ld ms\n", timeout_ms);
        handle_curl_timeout(EV_A_ &g->multi_timer, 0);
    }
    return 0;
}

/* This function gets called when curl_multi wants us to schedule or
 * teardown an I/O watcher */
int 
setup_curl_io_watcher(CURL *easy_h, 
                     curl_socket_t fd, 
                     int action,
                     GlobalInfo *g,
                     SockInfo *s)
{
    int events;
    struct ev_loop *loop = g->loop;

    printf("entering %s\n", __func__);
    if (action == CURL_POLL_NONE) {
        printf("action is CURL_POLL_NONE\n");
        /* Do nothing */
    } else if (action == CURL_POLL_REMOVE) {
        printf("action is CURL_POLL_REMOVE\n");
        printf("stopping curl watcher on fd %d\n", (int) fd);
        ev_io_stop(EV_A_ &s->watcher);
        free(s);
    } else {
        if (s == NULL) {
            /* Initialize a SockInfo struct to carry around */
            printf("initializing SockInfo\n");
            s = malloc(sizeof(SockInfo));
            curl_multi_assign(g->multi_h, fd, s);
            s->g = g;
            s->is_watching = 0;
        }
        if (s->is_watching) {
            printf("stopping curl watcher on fd %d\n", (int) fd);
            ev_io_stop(EV_A_ &s->watcher);
        } 
        if (action == CURL_POLL_IN) {
            printf("action is CURL_POLL_IN\n");
            events = EV_READ;
        } else if (action == CURL_POLL_OUT) {
            printf("action is CURL_POLL_OUT\n");
            events = EV_WRITE;
        } else if (action == CURL_POLL_INOUT) {
            printf("action is CURL_POLL_INOUT\n");
            events = EV_READ | EV_WRITE;
        }
        ev_io_init(&s->watcher, handle_curl_io, fd, events);
        printf("starting watcher on fd %d\n", (int) fd);
        ev_io_start(EV_A_ &s->watcher);
        s->watcher.data = s;
        s->is_watching = 1;
    }
    return 0;
}

int 
main(int argc, char **argv) 
{
    int i, len, ret, dns_listen_port;
    char *cfg_filename;
    GlobalInfo g;
    struct ares_addr_node *head_resolver_node;
    struct ares_options res_options;

    cfg_opt_t candidate_opts[] = {
        CFG_STR("check_address", NULL, CFGF_NODEFAULT),
        CFG_END()
    };
    cfg_opt_t name_opts[] =
    {
        CFG_SEC("candidate", candidate_opts, CFGF_TITLE | CFGF_NO_TITLE_DUPES | CFGF_MULTI),
        CFG_FLOAT("check_frequency", 60, CFGF_NONE),
        CFG_FLOAT("check_timeout", 0., CFGF_NONE),
        CFG_STR("check_method", "http", CFGF_NONE),
        CFG_STR("selection_method", "best_rtt", CFGF_NONE),
        CFG_STR("rtt_mode", "total", CFGF_NONE),
        CFG_STR("failure_mode", "none", CFGF_NONE),
        CFG_FLOAT("group_rtt_threshold", INFINITY, CFGF_NONE),
        CFG_FLOAT("max_rtt", INFINITY, CFGF_NONE),
        CFG_END()
    };
    cfg_opt_t opts[] = 
    {
        CFG_STR("data_file", "/var/tmp/har.dat", CFGF_NONE),
        CFG_INT("dns_listen_port", 15353, CFGF_NONE),
        CFG_STR_LIST("dns_bind_interfaces", NULL, CFGF_NODEFAULT),
        CFG_STR_LIST("nameservers", NULL, CFGF_NODEFAULT),
        CFG_FLOAT("resolver_timeout", 1., CFGF_NONE),
        CFG_SEC("name", name_opts, CFGF_TITLE | CFGF_NO_TITLE_DUPES | CFGF_MULTI), 
        CFG_END()
    };

    /* parse command-line args */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    cfg_filename = argv[1];

    /* initialize libraries */
    curl_global_init(CURL_GLOBAL_ALL);
    ares_library_init(ARES_LIB_INIT_ALL);

    /* initialize global data structure */
    memset(&g, 0, sizeof(g));
    g.cfg = cfg_init(opts, 0);
    g.loop = EV_DEFAULT;
    g.multi_h = curl_multi_init();
    g.multi_timer.data = &g;

    /* initialize our sqlite3 database and prepare statements for later
     * execution*/
    prepare_sql(&g);

    /* Configure curl with callbacks to call when it wants us to set up or
     * cancel a watcher */
    curl_multi_setopt(g.multi_h, CURLMOPT_SOCKETFUNCTION, setup_curl_io_watcher);
    curl_multi_setopt(g.multi_h, CURLMOPT_SOCKETDATA, &g);
    curl_multi_setopt(g.multi_h, CURLMOPT_TIMERFUNCTION, setup_curl_multi_timer);
    curl_multi_setopt(g.multi_h, CURLMOPT_TIMERDATA, &g);

    /* Parse config file */
    ret = cfg_parse(g.cfg, cfg_filename);
    if (ret == CFG_FILE_ERROR) {
        fprintf(stderr, "FATAL: Failed to open config file %s: %s\n", 
                cfg_filename, strerror(errno));
        exit(EXIT_FAILURE);
    } else if (ret == CFG_PARSE_ERROR) {
        fprintf(stderr, "FATAL: Failed to parse config file\n");
        exit(EXIT_FAILURE);
    }

    if ((len = cfg_size(g.cfg, "nameservers"))) {
        struct ares_addr_node *next_resolver_node = NULL;
        for (i = 0; i < len; i++) {
            char *addr = cfg_getnstr(g.cfg, "nameservers", i);
            head_resolver_node = malloc(sizeof(struct ares_addr_node));
            if ((strchr(addr, ':')) == NULL) {
                /* Looks like a v4 address */
                head_resolver_node->family = AF_INET;
                if ((ret = inet_pton(AF_INET, addr, &head_resolver_node->addr.addr4)) < 1) {
                    fprintf(stderr, "Invalid nameserver address '%s'\n", addr);
                    exit(EXIT_FAILURE);
                }
            } else {
                /* Looks like a v6 address */
                head_resolver_node->family = AF_INET6;
                if ((ret = inet_pton(AF_INET6, addr, &head_resolver_node->addr.addr6)) < 1) {
                    fprintf(stderr, "Invalid nameserver address '%s'\n", addr);
                    exit(EXIT_FAILURE);
                }
            }
            head_resolver_node->next = next_resolver_node;
            next_resolver_node = head_resolver_node;
        }
    } else {
        fprintf(stderr, "FATAL: No 'nameservers' declared in config file\n");
        exit(EXIT_FAILURE);
    }

    g.ares_io_watcher_active = 0;
    g.ares_timer_active = 0;

    /* set up ares */
    res_options.sock_state_cb = setup_ares_io_watcher;
    res_options.sock_state_cb_data = &g;
    res_options.timeout = cfg_getfloat(g.cfg, "resolver_timeout") * 1000;
    if ((ret = ares_init_options(&g.res_channel, &res_options, 
                                 ARES_OPT_SOCK_STATE_CB|ARES_OPT_TIMEOUTMS)) != ARES_SUCCESS) {
        fprintf(stderr, "ares_init_options: %s\n", ares_strerror(ret));
        exit(EXIT_FAILURE);
    }
    if ((ret = ares_set_servers(g.res_channel, head_resolver_node)) != ARES_SUCCESS) {
        fprintf(stderr, "ares_set_servers: %s\n", ares_strerror(ret));
        exit(EXIT_FAILURE);
    }

    /* parse check configurations */
    if ((len = cfg_size(g.cfg, "name"))) {
        for (i = 0; i < len; i++) {
            int j, ncandidates;
            GroupState group_state;
            cfg_t *name_cfg = cfg_getnsec(g.cfg, "name", i);
            const char *name = cfg_title(name_cfg);
            group_state.num_candidates = 0;
            group_state.last_selection = -1;
            name_cfg->opts->simple_value = &group_state;
            if ((ncandidates = cfg_size(name_cfg, "candidate"))) {
                for (j = 0; j < ncandidates; j++) {
                    CheckInfo *c = malloc(sizeof(CheckInfo));
                    c->g = &g;
                    c->name_cfg = name_cfg;
                    c->candidate_cfg = cfg_getnsec(name_cfg, "candidate", j);
                    init_check(c);
                }
            } else {
                fprintf(stderr, "FATAL: Configuration for name '%s' has no candidates\n",
                                name);
                exit(EXIT_FAILURE);
            }
        }
    } else {
        fprintf(stderr, "FATAL: No 'name' sections declared in config file\n");
        exit(EXIT_FAILURE);
    }

    dns_listen_port = cfg_getint(g.cfg, "dns_listen_port");
    if (dns_listen_port < 0 || dns_listen_port > 65535)  {
        fprintf(stderr, "FATAL: invalid dns_listen_port "
                        "(must be between 0 and 65535)\n");
        exit(EXIT_FAILURE);
    }

    if (cfg_size(g.cfg, "dns_bind_interfaces")) {
        for(i = 0; i < cfg_size(g.cfg, "dns_bind_interfaces"); i++) {
            init_dns_srv_watcher(&g, 
                                 cfg_getnstr(g.cfg, "dns_bind_interfaces", i),
                                 dns_listen_port);
        }
    } else {
        /* listen on all interfaces */
        init_dns_srv_watcher(&g, NULL, dns_listen_port);
    } 

    printf("Listening on port %d\n", dns_listen_port);

    /* start the event loop */
    ev_run(g.loop, 0);

    /* this is arguably unnecessary, since we're about to exit */
    cfg_free(g.cfg);

    return 0;
}
