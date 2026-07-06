#ifndef SECURITYMONITOR_H
#define SECURITYMONITOR_H

#include "eventbus.h"
#include "basethread.h"
#include "app.h"
#include "sai.h"
#include "addevent.h"
#include "removeevent.h"
#include <log4cpp/Category.hh>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <mutex>
#include <sys/types.h>

/*!
 * \class periodically samples each managed application's cgroup and
 * computes a composite Security Anomaly Index (SAI) from behavioural
 * factors compared to a per-app EWMA baseline. When the SAI exceeds a
 * threshold a SecurityEvent is published to the EventBus.
 */
class SecurityMonitor : public rmcommon::BaseThread {

public:
    /*! A pid paired with the starttime field from /proc/<pid>/stat (field 22),
     * used to detect pid recycling between the cgroup snapshot and later
     * per-process /proc reads. If the kernel recycles a pid that left the
     * cgroup into an unrelated process, the starttime differs and the sample
     * is dropped instead of reading the wrong process's /proc state. */
    struct PidSample {
        pid_t pid = 0;
        unsigned long starttime = 0;   // 0 == unreadable; verifyStarttime skips
    };

private:
    /*! Per-app baseline state kept across sampling periods. */
    struct AppBaseline {
        sec::Ewma fanout;
        sec::Ewma halfOpen;
        sec::Ewma forkRate;
        sec::Ewma cpuBurst;
        sec::Ewma egress;
        sec::Ewma memGrowth;
        // Identity of binaries seen during warmup, used by the B2
        // unexpected-exec factor. Stored as the real executable path from
        // /proc/<pid>/exe (readlink), not /proc/<pid>/comm: comm is
        // attacker-controlled via prctl(PR_SET_NAME), the exe symlink is not.
        std::set<std::string> knownExecs;
        bool rawSocketFired = false;
        uint64_t lastCpuUsec = 0;
        bool cpuInit = false;
        uint64_t lastTxBytes = 0;
        bool egressInit = false;
        uint64_t lastMemCurrent = 0;
        bool memInit = false;
    };

    log4cpp::Category &cat_;
    int securityPeriod_;
    rmcommon::EventBus &bus_;
    sec::SaiWeights weights_;
    float alpha_ = 0.3f;
    float publishThreshold_ = 0.4f;

    std::set<std::shared_ptr<rmcommon::App>> apps_;
    std::map<pid_t, AppBaseline> baselines_;
    std::mutex appsMutex_;

    void scanApp(std::shared_ptr<rmcommon::App> app);

    /*! Reads /proc/<pid>/stat field 22 (starttime in clock ticks since boot).
        Uniquely identifies a process lifetime, so a recycled pid has a
        different starttime. Returns 0 if the file cannot be parsed. */
    static unsigned long getProcessStarttime(pid_t pid);
    /*! Re-reads starttime for pid and returns true if it still matches the
        value captured at snapshot time. A return of false means the pid was
        recycled into a different process; callers must skip the per-pid read. */
    static bool verifyStarttime(pid_t pid, unsigned long expected);

    std::vector<PidSample> getCgroupPids(std::shared_ptr<rmcommon::App> app);
    /*! Maps each socket inode owned by the given pids to its pid. Pids whose
        starttime changed since the snapshot (recycled) are skipped so their
        /proc/<pid>/fd entries are not attributed to this cgroup. */
    std::map<ino_t, pid_t> socketInodeToPid(const std::vector<PidSample> &pids);
    /*! Counts distinct remote destinations and SYN_SENT sockets among the
        connections whose inode belongs to the given set (from the app's
        /proc/<netnsPid>/net/tcp{,6}). If netnsPid was recycled (starttime
        mismatch), reads nothing and reports zero to avoid attributing a
        foreign namespace's connections. */
    void countConnections(const std::set<ino_t> &inodes, pid_t netnsPid,
                          unsigned long netnsStarttime,
                          int &distinctDests, int &synSent, int &total);
    /*! Resolves the real executable path of a process via readlink on
        /proc/<pid>/exe, after verifying the pid has not been recycled
        (starttime must still match). Returns an empty string on error, on
        recycle, or if the link cannot be read. Unlike /proc/<pid>/comm, this
        path is set by the kernel at exec time and is not affected by
        prctl(PR_SET_NAME). */
    std::string getProcessExe(pid_t pid, unsigned long starttime);
    /*! Returns true if any of the app's socket inodes appears in the app's
        /proc/<netnsPid>/net/raw{,6} or /proc/<netnsPid>/net/packet. Returns
        false if netnsPid was recycled (foreign namespace must not be read). */
    bool hasRawSockets(const std::set<ino_t> &inodes, pid_t netnsPid,
                       unsigned long netnsStarttime);
    /*! Reads cumulative cgroup cpu usage in microseconds (cpu.stat usage_usec). */
    uint64_t getCpuUsec(std::shared_ptr<rmcommon::App> app);
    /*! Sums transmitted bytes across all interfaces (excluding lo) from the
        app's network namespace (/proc/<netnsPid>/net/dev). Returns 0 on error
        or if netnsPid was recycled. */
    uint64_t getTxBytes(pid_t netnsPid, unsigned long netnsStarttime);
    /*! Reads the cgroup current memory usage in bytes (memory.current). */
    uint64_t getMemCurrent(std::shared_ptr<rmcommon::App> app);

    virtual void run() override;

public:
    SecurityMonitor(rmcommon::EventBus &bus, int securityPeriod);
    ~SecurityMonitor();

    /*! Override the default SAI weights / EWMA alpha / publish threshold
        (from configuration). */
    void setSaiConfig(const sec::SaiWeights &weights, float alpha, float publishThreshold) {
        weights_ = weights;
        alpha_ = alpha;
        publishThreshold_ = publishThreshold;
        // Defence in depth: a config that zeroes all weights silently
        // disables detection. Warn so a misconfigured deployment is visible.
        float wsum = weights.fanout + weights.halfOpen + weights.forkRate +
                     weights.newExec + weights.cpuBurst + weights.egress +
                     weights.memGrowth + weights.rawSocket;
        if (wsum < 1e-3f)
            log4cpp::Category::getRoot().warn(
                "SECURITYMONITOR SAI weights sum to ~0; detection is disabled "
                "by configuration");
    }

    void processAddEvent(std::shared_ptr<const rmcommon::AddEvent> event);
    void processRemoveEvent(std::shared_ptr<const rmcommon::RemoveEvent> event);
};

#endif // SECURITYMONITOR_H
