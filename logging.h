#ifndef LOGGING_H
#define LOGGING_H

#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>

void initLogging() {
    boost::log::register_simple_formatter_factory<boost::log::trivial::severity_level, char>("Severity");
    boost::log::add_file_log(
        boost::log::keywords::file_name = "chat_app_%N.log",
        boost::log::keywords::rotation_size = 10 * 1024 * 1024,
        boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
        boost::log::keywords::format = "[%TimeStamp%] [%Severity%]: %Message%"
    );
    boost::log::add_console_log(
        std::cout,
        boost::log::keywords::format = "[%TimeStamp%] [%Severity%]: %Message%"
    );
    boost::log::add_common_attributes();
}

#endif // LOGGING_H
