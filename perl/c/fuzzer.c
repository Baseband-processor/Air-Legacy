#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <linux/limits.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>


// Struct to hold arguments passed to the monitor thread

volatile int stop = 0;   // the global 'stop fuzzing' variable. When set to 1, all threads will spool
                         // their cases to disk and exit.
int timeout_stop = 0; // similar to stop, but needed to know if the test cases should be saved.
pthread_mutex_t runlock;
int check_pid = 0; // server pid to check for crash.
int timeout_secs = 0; // time in seconds until fuzzing stops.
struct fuzzer_args fuzz; // Arguments for the fuzzer threads
char * output_dir = NULL; // directory for potential crashes

static unsigned long cases_sent = 0;
static unsigned long cases_jettisoned = 0;
static unsigned long paths = 0;




// timeout monitor's flow - checks if the elapsed time has passed the defined timeout, and if so triggers a stop
void * timer_job(void * args){
    time_t start_time;

    time(&start_time);
    while(stop == 0 && difftime(time(NULL), start_time) < timeout_secs){
        sleep(1);
    }

    if(stop == 0){
        pthread_mutex_lock(&runlock);
        printf("[!] Reached timeout\n");
        stop = 1;
        timeout_stop = 1;
        pthread_mutex_unlock(&runlock);
    }
    return NULL;
}

// worker thread, generate cases and sends them
void * worker(void * worker_args){
    struct worker_args *thread_info = (struct worker_args *)worker_args;
    printf("[.] Worker %u alive\n", thread_info->thread_id);

    int deterministic = 1;

    // Use the PID as the prefix for generation
    char prefix[25];
    sprintf(prefix,"%d",(int)syscall(SYS_gettid));

    // Testcases
    struct testcase * cases = 0x00;
    struct testcase * entry = 0x00;

    uint32_t exec_hash;
    int r;

    if(fuzz.shm_id > 0){
        printf("[.] Trace enabled\n");
        memset(fuzz.virgin_bits, 255, MAP_SIZE);
        fuzz.trace_bits = setup_shm(fuzz.shm_id);
    }

    if(fuzz.shm_id > 0 && fuzz.gen == RADAMSA){
        cases = load_testcases(fuzz.in_dir, ""); // load all cases from the provided dir
        entry = cases;

        if(fuzz.trace_bits == 0){
            return NULL;
        }

        // A server crash in calibration is not handled gracefully, this needs to be tidied up
        while(entry){
            memset(fuzz.trace_bits, 0x00, MAP_SIZE);
            if(fuzz.send(fuzz.host, fuzz.port, entry->data, entry->len) < 0){
                fatal("[!] Failure in calibration\n");
            }

            exec_hash = wait_for_bitmap(fuzz.trace_bits);
            if(exec_hash > 0){
                if(has_new_bits(fuzz.virgin_bits, fuzz.trace_bits) > 1){
                    r = calibrate_case(entry->data, entry->len, fuzz.trace_bits);
                    if(r == 0)
                        cases_jettisoned++;
                    else{
                        paths++;
                    }
                }
            }
            entry = entry->next;
            cases_sent++;
        }
        printf("\n[.] Loaded Paths: %lu Jettisoned: %lu\n", paths, cases_jettisoned);
        free_testcases(cases);
    }

    while(1){
        // generate the test cases
        if(fuzz.gen == BLAB){
            cases = generator_blab(CASE_COUNT, fuzz.grammar, fuzz.tmp_dir, prefix);
        }

        else if(fuzz.gen == RADAMSA){
            // Perform some deterministic mutations before going off to radamsa.
            // currently limited to the first thread.
            if(deterministic == 1 && thread_info->thread_id == 1){
                //printf("Performing deterministic mutations\n");

                struct testcase * orig_cases = load_testcases(fuzz.in_dir, ""); // load all cases from the provided dir
                struct testcase * orig_entry = orig_cases;

                while(orig_entry){
                    if(determ_fuzz(orig_entry->data, orig_entry->len, thread_info->thread_id) < 0){
                        free_testcases(orig_cases);
                        goto cleanup;
                    }
                    orig_entry = orig_entry->next;

                    if(stop < 0){
                        break;
                    }
                }
                free_testcases(orig_cases);

                if(deterministic > 0){
                    deterministic = 0;
                    if(fuzz.shm_id)
                        printf("[.] Deterministic mutations completed, sent: %lu paths: %lu\n", cases_sent, paths);
                    else
                        printf("[.] Deterministic mutations completed, sent: %lu\n", cases_sent);
                }

                if(stop < 0) // an error or crash occured during the deteministic steps
                    break;

                continue;
            }

            cases = generator_radamsa(CASE_COUNT, fuzz.in_dir, fuzz.tmp_dir, prefix);
        }

        if(send_cases(cases) < 0){
            goto cleanup;
        }
    }

cleanup:
    printf("[!] Thread %d exiting\n", thread_info->thread_id);
    return NULL;
}


int send_cases(void * cases){
    int ret = 0, r = 0;
    struct testcase * entry = cases;
    uint32_t exec_hash;

    while(entry){
        if(entry->len == 0){
            // no data in test case, go to next one. Radamsa will generate null
            // testcases sometimes...
            entry = entry->next;
            continue;
        }
        if(fuzz.shm_id){
            memset(fuzz.trace_bits, 0x00, MAP_SIZE);
            ret = fuzz.send(fuzz.host, fuzz.port, entry->data, entry->len);
            //stop = send_tcp(fuzz.host, fuzz.port, entry->data, entry->len);
            if(ret < 0)
                break;

            exec_hash = wait_for_bitmap(fuzz.trace_bits);
            if(exec_hash > 0){
                if(has_new_bits(fuzz.virgin_bits, fuzz.trace_bits) > 1){
                    r = calibrate_case(entry->data, entry->len, fuzz.trace_bits);
                    if(r == -1){
                        // crash during calibration?
                        ret = r;
                        break;
                    }
                    else if(r == 0){
                        cases_jettisoned++;
                    }
                    else{
                        paths++; // new case! save and perform some deterministic fuzzing
                        save_case(entry->data, entry->len, exec_hash, fuzz.in_dir);

                        if(fuzz.gen != BLAB){
                            determ_fuzz(entry->data, entry->len, 1); // attention defecit fuzzing
                        }
                    }
                }
            }
        }
        else {
            // no instrumentation
            ret = fuzz.send(fuzz.host, fuzz.port, entry->data, entry->len);

            if(ret < 0)
                break;
        }

        entry = entry->next;
        cases_sent++;
    }

    if(check_stop(cases, ret)<0){
        free_testcases(cases);
        return -1;
    }

    free_testcases(cases);
    return 0;
}

// checks the return code from send_cases et-al and sets the global stop variable if
// its time to stop fuzzing and saves the cases.
int check_stop(void * cases, int result){
    int ret = result;

    // if global stop, save cases
    pthread_mutex_lock(&runlock);
    if(stop == 1){
        // save cases
        if(!timeout_stop){
            save_testcases(cases, output_dir);
        }
        pthread_mutex_unlock(&runlock);
        return -1;
    }
    pthread_mutex_unlock(&runlock);

    // If process id is supplied, check it exists and set stop if it doesn't
    if(check_pid > 0){
        if((pid_exists(check_pid)) == -1){
            ret = -1;
        }
        else{
            ret = 0;
        }
    }

    if(fuzz.check_script){
        int r;
        r = run_check(fuzz.check_script);
        if( r != 1){
            printf("[!] Check script %s returned %d, stopping\n", fuzz.check_script, r);
            ret = -1;
        }
        else{
            ret = 0;
        }
    }

    if(ret == -1){
        // We have experienced a crash. set the global stop var
        pthread_mutex_lock(&runlock);
        stop = 1;
        save_testcases(cases, output_dir);
        pthread_mutex_unlock(&runlock);
    }

    return ret;
}

/* Calibrate a new testcase. Returns 1 if the testcase behaves deterministically, 0 if it does not
 * EG: has variable behaviour. Without this, non deterministic features would cause a bunch of
 * tiny, useless test cases. Return -1 on failure. Timeout on waiting for the bitmap to stop changing
 * is an immediate 0.
 */
int calibrate_case(char * testcase, unsigned long len, uint8_t * trace_bits){
    uint32_t hash, tmp_hash, i;

    memset(trace_bits, 0x00, MAP_SIZE);
    if(fuzz.send(fuzz.host, fuzz.port, testcase, len) < 0){
        return -1;
    }

    hash = wait_for_bitmap(trace_bits); // check null
    if(hash == 0 || hash == NULL_HASH) // unstable test case, bitmap still changing after 2 seconds, or no bitmap change
        return 0;

    for(i = 0; i < 4; i++){
        memset(trace_bits, 0x00, MAP_SIZE);
        if(fuzz.send(fuzz.host, fuzz.port, testcase, len) < 0){
            return -1;
        }
        tmp_hash = wait_for_bitmap(trace_bits);
        if(tmp_hash != hash){
            // printf("[!] Non deterministic testcase detected\n");
            return 0;
        }
    }

    // timing and case trimming should eventually go here

    return 1;
}

int pid_exists(int pid){
    struct stat s;
    char path[PATH_MAX];

    sprintf(path, "/proc/%d", pid);
    if(stat(path, &s) == -1){
        // PID not found
        printf("[!!] PID %d not found. Check for server crash\n", pid);
        return -1;
    }

    // PID found
    return 0;
}

int run_check(char * script){

    if(access(script, X_OK) < 0){
        fatal("[!] Error accessing check script %s: %s\n", script, strerror(errno));
    }

    int out_pipe[2];
    int err_pipe[2];
    pid_t pid;
    char ret[2];
    memset(ret, 0x00, 2);

    if(pipe(out_pipe) < 0 || pipe(err_pipe) < 0){
        fatal("[!] Error with pipe: %s\n", strerror(errno));
    }
    if((pid = fork()) == 0){
            dup2(err_pipe[1], 2);
            dup2(out_pipe[1], 1);
            close(out_pipe[0]);
            close(out_pipe[1]);
            close(err_pipe[0]);
            close(err_pipe[1]);

            char *args[] = {script, 0};
            execv(args[0], args);

            exit(0);
    }

    else if(pid < 0){
            fatal("[!] FORK FAILED!\n");
    }
    else{
        close(err_pipe[1]);
        close(out_pipe[1]);
        waitpid(pid, NULL, 0);
        if(read(out_pipe[0], ret, 1) < 0){
            fatal("read() failed");
        };
        close(err_pipe[0]);
        close(out_pipe[0]);
        return atoi(&ret[0]);
    }

    return -1;
}
