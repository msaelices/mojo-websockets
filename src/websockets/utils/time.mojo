# Code adapted from https://github.com/thatstoasty/small-time/
# We just needed a small subset considering always UTC

from collections import InlineList, Optional
from memory import UnsafePointer, Pointer
from sys import external_call


@register_passable("trivial")
struct Tm:
    """C Tm struct."""

    var tm_sec: Int32
    """Seconds."""
    var tm_min: Int32
    """Minutes."""
    var tm_hour: Int32
    """Hour."""
    var tm_mday: Int32
    """Day of the month."""
    var tm_mon: Int32
    """Month."""
    var tm_year: Int32
    """Year minus 1900."""
    var tm_wday: Int32
    """Day of the week."""
    var tm_yday: Int32
    """Day of the year."""
    var tm_isdst: Int32
    """Daylight savings flag."""
    var tm_gmtoff: Int64
    """Localtime zone offset seconds."""

    fn __init__(out self):
        """Initializes a new time struct."""
        self.tm_sec = 0
        self.tm_min = 0
        self.tm_hour = 0
        self.tm_mday = 0
        self.tm_mon = 0
        self.tm_year = 0
        self.tm_wday = 0
        self.tm_yday = 0
        self.tm_isdst = 0
        self.tm_gmtoff = 0


@register_passable("trivial")
struct TimeVal:
    """Time value."""
    var tv_sec: Int
    """Seconds."""
    var tv_usec: Int
    """Microseconds."""

    fn __init__(out self, tv_sec: Int = 0, tv_usec: Int = 0):
        """Initializes a new time value.
        
        Args:
            tv_sec: Seconds.
            tv_usec: Microseconds.
        """
        self.tv_sec = tv_sec
        self.tv_usec = tv_usec

@value
struct TimeZone(Stringable):
    """Timezone."""
    var offset: Int
    """Offset in seconds."""
    var name: Optional[String]
    """Name of the timezone."""

    fn __init__(out self, offset: Int = 0, name: String = "utc"):
        """Initializes a new timezone.

        Args:
            offset: Offset in seconds.
            name: Name of the timezone.
        """
        self.offset = offset
        self.name = name

    fn __str__(self) -> String:
        """String representation of the timezone.

        Returns:
            String representation.
        """
        if self.name:
            return self.name.value()
        return ""

    fn __bool__(self) -> Bool:
        """Checks if the timezone is valid.

        Returns:
            True if the timezone is valid, False otherwise.
        """
        return self.name.__bool__()

    fn format(self, sep: String = ":") -> String:
        """Formats the timezone.

        Args:
            sep: Separator between hours and minutes.
        
        Returns:
            Formatted timezone.
        """
        var sign: String
        var offset_abs: Int
        if self.offset < 0:
            sign = "-"
            offset_abs = -self.offset
        else:
            sign = "+"
            offset_abs = self.offset
        var hh = offset_abs // 3600
        var mm = offset_abs % 3600
        return sign + String(hh).rjust(2, "0") + sep + String(mm).rjust(2, "0")



@value
struct SmallTime(Stringable, Writable, Representable):
    """Datetime representation."""
    var year: Int
    """Year."""
    var month: Int
    """Month."""
    var day: Int
    """Day."""
    var hour: Int
    """Hour."""
    var minute: Int
    """Minute."""
    var second: Int
    """Second."""
    var microsecond: Int
    """Microsecond."""
    var tz: TimeZone
    """Time zone."""

    fn __init__(
        out self,
        year: Int,
        month: Int,
        day: Int,
        hour: Int = 0,
        minute: Int = 0,
        second: Int = 0,
        microsecond: Int = 0,
        tz: TimeZone = TimeZone(),
    ):
        """Initializes a new SmallTime instance.

        Args:
            year: Year.
            month: Month.
            day: Day.
            hour: Hour.
            minute: Minute.
            second: Second.
            microsecond: Microsecond.
            tz: Time zone.
        """
        self.year = year
        self.month = month
        self.day = day
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond
        self.tz = tz


    fn __str__(self) -> String:
        """Return the string representation of the `SmallTime` instance.
        
        Returns:
            The string representation.
        """
        return self.isoformat()

    fn __repr__(self) -> String:
        """Return the string representation of the `SmallTime` instance.
        
        Returns:
            The string representation.
        """
        return String(self)

    fn isoformat[timespec: String = "auto"](self, sep: String = "T") -> String:
        """Return the time formatted according to ISO.

        Parameters:
            timespec: The number of additional terms of the time to include.

        Args:
            sep: The separator between date and time.
        
        Returns:
            The formatted string.
        
        Notes:
            The full format looks like 'YYYY-MM-DD HH:MM:SS.mmmmmm'.

            If self.tzinfo is not None, the UTC offset is also attached, giving
            giving a full format of 'YYYY-MM-DD HH:MM:SS.mmmmmm+HH:MM'.

            Optional argument sep specifies the separator between date and
            time, default 'T'.

            The optional argument timespec specifies the number of additional
            terms of the time to include. Valid options are 'auto', 'hours',
            'minutes', 'seconds', 'milliseconds' and 'microseconds'.
        """
        alias valid = InlineList[String, 6]("auto", "hours", "minutes", "seconds", "milliseconds", "microseconds")
        """Valid timespec values."""
        constrained[
            timespec in valid,
            msg="timespec must be one of the following: 'auto', 'hours', 'minutes', 'seconds', 'milliseconds', 'microseconds'",
        ]()
        var date_str = String(
            String(self.year).rjust(4, "0"), "-", String(self.month).rjust(2, "0"), "-", String(self.day).rjust(2, "0")
        )
        
        var time_str = String("")

        @parameter
        if timespec == "auto" or timespec == "microseconds":
            time_str = String(
                String(self.hour).rjust(2, "0")
                , ":"
                , String(self.minute).rjust(2, "0")
                , ":"
                , String(self.second).rjust(2, "0")
                , "."
                , String(self.microsecond).rjust(6, "0")
            )
        elif timespec == "milliseconds":
            time_str = String(
                String(self.hour).rjust(2, "0")
                , ":"
                , String(self.minute).rjust(2, "0")
                , ":"
                , String(self.second).rjust(2, "0")
                , "."
                , String(self.microsecond // 1000).rjust(3, "0")
            )
        elif timespec == "seconds":
            time_str = String(
                String(self.hour).rjust(2, "0")
                , ":"
                , String(self.minute).rjust(2, "0")
                , ":"
                , String(self.second).rjust(2, "0")
            )
        elif timespec == "minutes":
            time_str = String(String(self.hour).rjust(2, "0"), ":", String(self.minute).rjust(2, "0"))
        elif timespec == "hours":
            time_str = String(self.hour).rjust(2, "0")

        if not self.tz:
            return sep.join(date_str, time_str)
        else:
            return sep.join(date_str, time_str) + self.tz.format()

    fn write_to[W: Writer, //](self, mut writer: W):
        """Writes a representation of the `SmallTime` instance to a writer.

        Parameters:
            W: The type of writer to write the contents to.

        Args:
            writer: The writer to write the contents to.
        """
        @parameter
        fn write_optional(opt: Optional[String]):
            if opt:
                writer.write(repr(opt.value()))
            else:
                writer.write(repr(None))

        writer.write("SmallTime(",
        "year=", self.year,
        ", month=", self.month,
        ", day=", self.day,
        ", hour=", self.hour,
        ", minute=", self.minute,
        ", second=", self.second,
        ", microsecond=", self.microsecond,
        )
        writer.write(", tz=", "TimeZone(",
        "offset=", self.tz.offset,
        ", name=")
        write_optional(self.tz.name)
        writer.write(")")
        writer.write(")")


fn from_timestamp(t: TimeVal) raises -> SmallTime:
    """Create a UTC SmallTime instance from a timestamp.

    Args:
        t: The timestamp.
    
    Returns:
        The SmallTime instance.
    
    Raises:
        Error: If the timestamp is invalid.
    """

    return _validate_timestamp(gmtime(t.tv_sec), t, TimeZone(0, String("UTC")))


fn now(*, utc: Bool = False) raises -> SmallTime:
    """Return the current time in UTC or local time.

    Args:
        utc: If True, return the current time in UTC. Otherwise, return the current time in local time.
    
    Returns:
        The current time.
    """
    return from_timestamp(gettimeofday())


fn gmtime(owned tv_sec: Int) -> Tm:
    """Converts a time value to a broken-down UTC time.
    
    Args:
        tv_sec: Time value in seconds since the Epoch.
    
    Returns:
        Broken down UTC time.
    """
    var tm = external_call["gmtime", UnsafePointer[Tm]](Pointer.address_of(tv_sec)).take_pointee()
    return tm


fn gettimeofday() -> TimeVal:
    """Gets the current time. It's a wrapper around libc `gettimeofday`.
    
    Returns:
        Current time.
    """
    var tv = TimeVal()
    _ = external_call["gettimeofday", NoneType](Pointer.address_of(tv), 0)
    return tv


fn _validate_timestamp(tm: Tm, time_val: TimeVal, time_zone: TimeZone) raises -> SmallTime:
    """Validate the timestamp.

    Args:
        tm: The time struct.
        time_val: The time value.
        time_zone: The time zone.
    
    Returns:
        The validated timestamp.
    
    Raises:
        Error: If the timestamp is invalid.
    """
    var year = Int(tm.tm_year) + 1900
    if not -1 < year < 10000:
        raise Error("The year parsed out from the timestamp is too large or negative. Received: " + String(year))

    var month = Int(tm.tm_mon) + 1
    if not -1 < month < 13:
        raise Error("The month parsed out from the timestamp is too large or negative. Received: " + String(month))

    var day = Int(tm.tm_mday)
    if not -1 < day < 32:
        raise Error(
            "The day of the month parsed out from the timestamp is too large or negative. Received: " + String(day)
        )

    var hours = Int(tm.tm_hour)
    if not -1 < hours < 25:
        raise Error("The hour parsed out from the timestamp is too large or negative. Received: " + String(hours))

    var minutes = Int(tm.tm_min)
    if not -1 < minutes < 61:
        raise Error("The minutes parsed out from the timestamp is too large or negative. Received: " + String(minutes))

    var seconds = Int(tm.tm_sec)
    if not -1 < seconds < 61:
        raise Error(
            "The day of the month parsed out from the timestamp is too large or negative. Received: " + String(seconds)
        )

    var microseconds = time_val.tv_usec
    if microseconds < 0:
        raise Error("Received negative microseconds. Received: " + String(microseconds))

    return SmallTime(
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
        microseconds,
        time_zone,
    )
