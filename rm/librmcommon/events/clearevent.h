#ifndef CLEAREVENT_H
#define CLEAREVENT_H

#include "baseevent.h"
#include <sys/types.h>

namespace rmcommon {

/*!
 * \class operator request (via HTTP /clear) to thaw a quarantined
 * application and reset its containment state.
 */
class ClearEvent : public BaseEvent {
    pid_t pid_;
public:
    explicit ClearEvent(pid_t pid) :
        BaseEvent("ClearEvent"),
        pid_(pid)
    {}

    pid_t getPid() const noexcept {
        return pid_;
    }

    void printOnOstream(std::ostream &os) const override {
        os << "{\"clear_pid\":" << pid_ << "}";
    }
};

} // namespace rmcommon

#endif // CLEAREVENT_H
