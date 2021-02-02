// This might require setting capabilities to run as non-root:
// sudo setcap 'cap_net_raw,cap_net_admin+eip' /absolute/path/to/atc_mi_collector

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <iostream>
#include <signal.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <vector>
#include <array>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <iomanip>
#include <thread>

#include <prometheus/gauge.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include "aliases.h"


#define HCI_STATE_NONE       0
#define HCI_STATE_OPEN       2
#define HCI_STATE_SCANNING   3
#define HCI_STATE_FILTERING  4

struct hci_state {
        int device_id;
        int device_handle;
        struct hci_filter original_filter;
        int state;
        int has_error;
        char error_message[1024];
} hci_state;

#define EIR_FLAGS                   0X01
#define EIR_NAME_SHORT              0x08
#define EIR_NAME_COMPLETE           0x09
#define EIR_SERVICE_DATA            0x16
#define EIR_MANUFACTURE_SPECIFIC    0xFF

using namespace std;



struct hci_state open_default_hci_device()
{
        struct hci_state current_hci_state = {0};

        current_hci_state.device_id = hci_get_route(NULL);

        if ((current_hci_state.device_handle = hci_open_dev(current_hci_state.device_id)) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not open device: %s", strerror(errno));
                return current_hci_state;
        }

        // Set fd non-blocking
        int on = 1;
        if (ioctl(current_hci_state.device_handle, FIONBIO, (char *)&on) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could set device to non-blocking: %s", strerror(errno));
                return current_hci_state;
        }

        current_hci_state.state = HCI_STATE_OPEN;

        return current_hci_state;
}

void start_hci_scan(struct hci_state current_hci_state)
{
        if (hci_le_set_scan_parameters(current_hci_state.device_handle, 0x01, htobs(0x0010), htobs(0x0010), 0x00, 0x00, 1000) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to set scan parameters: %s", strerror(errno));
                return;
        }

        if (hci_le_set_scan_enable(current_hci_state.device_handle, 0x01, 1, 1000) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Failed to enable scan: %s", strerror(errno));
                return;
        }

        current_hci_state.state = HCI_STATE_SCANNING;

        // Save the current HCI filter
        socklen_t olen = sizeof(current_hci_state.original_filter);
        if (getsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, &olen) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not get socket options: %s", strerror(errno));
                return;
        }

        // Create and set the new filter
        struct hci_filter new_filter;

        hci_filter_clear(&new_filter);
        hci_filter_set_ptype(HCI_EVENT_PKT, &new_filter);
        hci_filter_set_event(EVT_LE_META_EVENT, &new_filter);


        if (setsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &new_filter, sizeof(new_filter)) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Could not set socket options: %s", strerror(errno));
                return;
        }

        current_hci_state.state = HCI_STATE_FILTERING;
}

void stop_hci_scan(struct hci_state current_hci_state)
{
        if (current_hci_state.state == HCI_STATE_FILTERING)
        {
                current_hci_state.state = HCI_STATE_SCANNING;
                setsockopt(current_hci_state.device_handle, SOL_HCI, HCI_FILTER, &current_hci_state.original_filter, sizeof(current_hci_state.original_filter));
        }

        if (hci_le_set_scan_enable(current_hci_state.device_handle, 0x00, 1, 1000) < 0)
        {
                current_hci_state.has_error = 1;
                snprintf(current_hci_state.error_message, sizeof(current_hci_state.error_message), "Disable scan failed: %s", strerror(errno));
        }

        current_hci_state.state = HCI_STATE_OPEN;
}

void error_check_and_exit(struct hci_state current_hci_state)
{
        if (current_hci_state.has_error)
        {
                cout << "ERROR: " << current_hci_state.error_message << endl;
                exit(1);
        }
}

class BtAddr {
public:
BtAddr(const bdaddr_t& addr) : addr_(0) {
        for(int i=0; i<6; i++) {
                addr_ = (addr_ << 2) | addr.b[i];
        }
}
std::size_t operator()() const {
        return addr_;
}
friend std::ostream& operator<<(std::ostream& os, const BtAddr& a);
friend bool operator==(const BtAddr& lhs, const BtAddr& rhs);
private:
int64_t addr_;
};

std::ostream& operator<<(std::ostream& os, const BtAddr& a) {
        os << std::hex;
        for(int i=0; i<6; i++) {
                if (i) os << ":";
                os << int((a.addr_ >> (5-i) * 2) & 0xff);
        }
        return os;
}

bool operator==(const BtAddr& lhs, const BtAddr& rhs) {
        return lhs.addr_ == rhs.addr_;
}

namespace std
{
template<> struct hash<BtAddr>
{
        std::size_t operator()(BtAddr const& a) const noexcept
        {
                return a();
        }
};
}

struct Atc1441 {
        int16_t temperature;
        uint8_t humidity_percent;
        uint8_t battery_percent;
        int16_t battery_mv;
        uint8_t count;
};
std::ostream& operator<<(std::ostream& os, const Atc1441& a) {
        os << std::dec;
        os << "temperature: " << a.temperature / 10.0 << std::endl;
        os << "humidity_percent: " << int(a.humidity_percent) << std::endl;
        os << "battery_percent: " << int(a.battery_percent) << std::endl;
        os << "battery_v: " << a.battery_mv / 1000.0 << std::endl;
        os << "count: " << int(a.count) << std::endl;
        return os;
}

uint16_t swap_endian(uint16_t v) {
        return v >> 8 | v << 8;
}

struct MetricFamilies {
        explicit MetricFamilies(prometheus::Registry& registry) :
                temperature(prometheus::BuildGauge().Name("btle_temperature_celsuis").Help("Temperature").Register(registry)),
                humidity(prometheus::BuildGauge().Name("btle_humidity_percent").Help("Humidity").Register(registry)),
                battery_level(prometheus::BuildGauge().Name("btle_battery_percent").Help("Battery Level").Register(registry)),
                battery_voltage(prometheus::BuildGauge().Name("btle_battery_volts").Help("Battery Voltage").Register(registry)){
        }
        prometheus::Family<prometheus::Gauge>& temperature;
        prometheus::Family<prometheus::Gauge>& humidity;
        prometheus::Family<prometheus::Gauge>& battery_level;
        prometheus::Family<prometheus::Gauge>& battery_voltage;
};

struct Metrics {
        Metrics(const std::string& name, MetricFamilies& fams) : families(fams),
                temperature(families.temperature.Add({{"name", name}})),
                humidity(families.humidity.Add({{"name", name}})),
                battery_level(families.battery_level.Add({{"name", name}})),
                battery_voltage(families.battery_voltage.Add({{"name", name}})) {
        }
        ~Metrics() {
                families.temperature.Remove(&temperature);
                families.humidity.Remove(&humidity);
                families.battery_level.Remove(&battery_level);
                families.battery_voltage.Remove(&battery_voltage);
        }
        MetricFamilies& families;
        prometheus::Gauge& temperature;
        prometheus::Gauge& humidity;
        prometheus::Gauge& battery_level;
        prometheus::Gauge& battery_voltage;
};

class Device {
public:
Device() {
};
const std::string& name() const {
        return name_;
}
void parse_packet(const uint8_t* data, int length) {
        last_seen_ = std::chrono::system_clock::now();
        const uint8_t* end = data + length;
        while(data < end) {
                size_t data_len = *data++;
                if (data + data_len > end)
                {
                        std::cerr << "EIR data length is longer than EIR packet length. " << std::dec << static_cast<const void*>(data) << " + " << data_len << " > " << static_cast<const void*>(end) << endl;
                        return;
                }
                parse_data(data, data_len);
                data += data_len;
        }
}
void set_metrics(MetricFamilies& families) {
        if (!atc1441_.has_value()) return;
        if (!metrics_.has_value()) {
                metrics_.emplace(maybe_alias(name_), families);
        }
        metrics_->temperature.Set(atc1441_->temperature / 10.0);
        metrics_->humidity.Set(atc1441_->humidity_percent);
        metrics_->battery_level.Set(atc1441_->battery_percent);
        metrics_->battery_voltage.Set(atc1441_->battery_mv / 1000.0);
}
std::chrono::seconds age() const {
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - last_seen_);
}

friend std::ostream& operator<<(std::ostream& os, const Device& d);
private:
void parse_atc1441(const uint8_t* data, std::size_t length) {
        Atc1441 a;
        if (length != 13) {
                std::cerr << "wrong length:" << std::dec << length;
                return;
        }
        a.temperature = swap_endian(*reinterpret_cast<const uint16_t*>(data + 6));
        a.humidity_percent = data[8];
        a.battery_percent = data[9];
        a.battery_mv = swap_endian(*reinterpret_cast<const uint16_t*>(data + 10));
        a.count = data[12];
        atc1441_ = a;
}
void parse_data(const uint8_t* data, int length) {
        length--;
        const uint8_t tag = *data++;
        uint16_t uuid = reinterpret_cast<const uint16_t*>(data)[0];
        switch(tag) {
        case EIR_NAME_SHORT:
        case EIR_NAME_COMPLETE:
                name_ = std::string(reinterpret_cast<const char*>(data), length);
                break;
        case EIR_SERVICE_DATA:
                if (uuid == 0x181a) {
                        parse_atc1441(data + 2, length - 2);
                        return;
                } else {
                        service_data_.clear();
                        for (int i = 0; i < length; i++)
                        {
                                service_data_.push_back(data[i]);
                        }
                }
                break;
        default:
                std::vector<uint8_t> v;
                for (int i = 0; i < length; i++)
                {
                        v.push_back(data[i]);
                }
                data_[tag] = std::move(v);
        }
}

std::chrono::time_point<std::chrono::system_clock> last_seen_;
std::string name_;
std::vector<uint8_t> service_data_;
std::unordered_map<uint8_t, std::vector<uint8_t> > data_;
std::optional<Atc1441> atc1441_;
std::optional<Metrics> metrics_;
};

std::ostream& operator<<(std::ostream& os, const Device& d) {
        auto t_c = std::chrono::system_clock::to_time_t(d.last_seen_);
        os << "last seen: " << std::put_time(std::localtime(&t_c), "%F %T") << std::endl;
        os << "Name: " << d.name_ << std::endl;
        if (d.atc1441_.has_value()) {
                os << *d.atc1441_;
        }
        os << std::hex;
        if (!d.service_data_.empty()) {
                os << "Service Data: ";
                for(unsigned int i = 0; i < d.service_data_.size(); i++) {
                        if (i) os << " ";
                        os << std::setfill('0') << std::setw(2) << int(d.service_data_[i]);
                }
                os << std::endl;
        }
        for(const auto& [tag, v] : d.data_) {
                os << "tag[0x" << std::hex << std::setfill('0') << std::setw(2) << int(tag) << "]: ";
                for(unsigned int i = 0; i < v.size(); i++) {
                        if (i) os << " ";
                        os << std::setfill('0') << std::setw(2) << int(v[i]);
                }
                os << std::endl;
        }
        return os;
}

class AtcMiCollector {
public:
explicit AtcMiCollector(prometheus::Registry& registry) : families_(registry) {
        current_hci_state_ = open_default_hci_device();
        error_check_and_exit(current_hci_state_);
        stop_hci_scan(current_hci_state_);
}

void scan() {
        start_hci_scan(current_hci_state_);

        error_check_and_exit(current_hci_state_);

        int done = 0;
        int error = 0;
        auto scan_start = std::chrono::system_clock::now();
        while (!done && !error)
        {
                if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - scan_start) > std::chrono::seconds(60)) {
                        done = 1;
                }
                int len = 0;
                unsigned char buf[HCI_MAX_EVENT_SIZE];
                while ((len = read(current_hci_state_.device_handle, buf, sizeof(buf))) < 0)
                {
                        if (errno == EINTR || errno == EAGAIN)
                        {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                                continue;
                        }
                        error = 1;
                }

                if (!done && !error)
                {
                        evt_le_meta_event *meta = (evt_le_meta_event*)(((uint8_t *)&buf) + (1 + HCI_EVENT_HDR_SIZE));

                        len -= (1 + HCI_EVENT_HDR_SIZE);

                        if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
                        {
                                cout << "continue" << endl;
                                continue;
                        }

                        le_advertising_info *info = (le_advertising_info *) (meta->data + 1);
                        BtAddr addr(info->bdaddr);
                        auto& device = devices_[addr];
                        device.parse_packet(info->data, info->length);
                        if (device.name().rfind("ATC_", 0) == 0) {
                                device.set_metrics(families_);
                                std::cout << "#############################" << endl;
                                std::cout << "Event: 0x" << std::hex << (int)info->evt_type << std::endl;
                                std::cout << "bdaddr: " << addr << std::endl;
                                std::cout << device;
                                std::cout << std::endl;
                        }
                }
        }

        if (error)
        {
                cout << "Error scanning." << endl;
        }

        stop_hci_scan(current_hci_state_);
}

void prune_old_devices() {
        for(auto it = devices_.begin(); it != devices_.end();) {
                if (it->second.age() > std::chrono::minutes(10)) {
                        std::cerr << "Haven't seen device [" << it->first << ", " << it->second << "] for too long. Erasing." << std::endl;
                        auto it_copy = it;
                        ++it;
                        devices_.erase(it_copy);
                } else {
                        ++it;
                }
        }
}

private:

struct hci_state current_hci_state_;
std::unordered_map<BtAddr, Device> devices_;
MetricFamilies families_;
};

int main(void)
{
        prometheus::Exposer exposer{"127.0.0.1:8001"};
        auto registry = std::make_shared<prometheus::Registry>();
        AtcMiCollector collector(*registry);
        exposer.RegisterCollectable(registry);

        while(true) {
                collector.scan();
                collector.prune_old_devices();
        }
        return 0;
}
