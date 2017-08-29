package parserpac;

import parserpac.query.*;

import java.io.*;
import java.nio.file.Path;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

public class LogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {
    private Path logDir;

    public LogParser(Path logDir) {
        this.logDir = logDir;
    }

    @Override
    public int getNumberOfUniqueIPs(Date after, Date before) {
        List<Parser> list1 = Parser.parseLog(logDir);
        List<Parser> list2 = Parser.getLogsFromTo(list1, after, before);
        Set<String> iPs = new HashSet<>();
        for (Parser p :
                list2) {
            iPs.add(p.ip);
        }
        return iPs.size();
    }

    @Override
    public Set<String> getUniqueIPs(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> list2 = Parser.getLogsFromTo(userList, after, before);
        Set<String> iPs = new HashSet<>();
        for (Parser p :
                list2) {
            iPs.add(p.ip);
        }
        return iPs;
    }

    @Override
    public Set<String> getIPsForUser(String user, Date after, Date before) {
        List<Parser> list1 = Parser.parseLog(logDir);
        List<Parser> list2 = Parser.getLogsFromTo(list1, after, before);
        Set<String> iPs = new HashSet<>();
        for (Parser p :
                list2) {
            if (p.user.equals(user)) {
                iPs.add(p.ip);
            }
        }
        return iPs;

    }

    @Override
    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        List<Parser> list1 = Parser.parseLog(logDir);
        List<Parser> list2 = Parser.getLogsFromTo(list1, after, before);
        Set<String> iPs = new HashSet<>();
        for (Parser p :
                list2) {
            if (p.event.contains(event.toString())) {
                iPs.add(p.ip);
            }
        }
        return iPs;
    }

    @Override
    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        List<Parser> list1 = Parser.parseLog(logDir);
        List<Parser> list2 = Parser.getLogsFromTo(list1, after, before);
        Set<String> iPs = new HashSet<>();
        for (Parser p :
                list2) {
            if (p.status.equals(status.toString())) {
                iPs.add(p.ip);
            }
        }
        return iPs;
    }

    @Override
    public Set<String> getAllUsers() {
        List<Parser> userList = Parser.parseLog(logDir);
        Set<String> users = new HashSet<>();
        for (Parser p :
                userList) {
            users.add(p.user);
        }
        return users;
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> users = new HashSet<>();
        for (Parser p :
                listPeriod) {
            users.add(p.user);
        }
        return users.size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                events.add(p.event);
            }
        }
        return events.size();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByIp = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.ip.equals(ip)) {
                usersByIp.add(p.user);
            }
        }
        return usersByIp;
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByLogin = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.LOGIN.toString())) {
                usersByLogin.add(p.user);
            }
        }
        return usersByLogin;
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByDownloadPlugin = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                usersByDownloadPlugin.add(p.user);
            }
        }
        return usersByDownloadPlugin;
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByWriteMessage = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                usersByWriteMessage.add(p.user);
            }
        }
        return usersByWriteMessage;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersBySolveTask = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.SOLVE_TASK.toString())) {
                usersBySolveTask.add(p.user);
            }
        }
        return usersBySolveTask;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersBySolveTaskInt = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.SOLVE_TASK.toString())) {
                if (p.event.contains(String.valueOf(task))) {
                    usersBySolveTaskInt.add(p.user);
                }
            }
        }
        return usersBySolveTaskInt;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByDoneTask = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.DONE_TASK.toString())) {
                usersByDoneTask.add(p.user);
            }
        }
        return usersByDoneTask;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<String> usersByDoneTaskInt = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.DONE_TASK.toString())) {
                if (p.event.contains(String.valueOf(task))) {
                    usersByDoneTaskInt.add(p.user);
                }
            }
        }
        return usersByDoneTaskInt;
    }

    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Date> dateByUserAndEvent = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.contains(event.toString())) {
                    dateByUserAndEvent.add(p.date);
                }
            }
        }
        return dateByUserAndEvent;
    }

    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Date> dateByStatusFailed = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.status.equals(Status.FAILED.toString())) {
                dateByStatusFailed.add(p.date);
            }
        }
        return dateByStatusFailed;
    }

    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Date> dateByStatusError = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.status.equals(Status.ERROR.toString())) {
                dateByStatusError.add(p.date);
            }
        }
        return dateByStatusError;
    }

    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        TreeSet<Date> dateUserLoggedFirstTime = new TreeSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.contains(Event.LOGIN.toString())) {
                    dateUserLoggedFirstTime.add(p.date);
                }
            }
        }
        if (!dateUserLoggedFirstTime.isEmpty()) {
            return dateUserLoggedFirstTime.first();
        } else {
            return null;
        }
    }

    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        TreeSet<Date> dateUserSolvedTaskFirstTime = new TreeSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.contains(Event.SOLVE_TASK.toString())) {
                    if (p.event.contains(String.valueOf(task))) {
                        dateUserSolvedTaskFirstTime.add(p.date);
                    }
                }
            }
        }
        if (!dateUserSolvedTaskFirstTime.isEmpty()) {
            return dateUserSolvedTaskFirstTime.first();
        } else {
            return null;
        }
    }

    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        TreeSet<Date> dateUserDoneTaskFirstTime = new TreeSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.contains(Event.DONE_TASK.toString())) {
                    if (p.event.contains(String.valueOf(task))) {
                        dateUserDoneTaskFirstTime.add(p.date);
                    }
                }
            }
        }
        if (!dateUserDoneTaskFirstTime.isEmpty()) {
            return dateUserDoneTaskFirstTime.first();
        } else {
            return null;
        }
    }

    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Date> dateByUserWroteMessage = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.equals(Event.WRITE_MESSAGE.toString())) {
                    dateByUserWroteMessage.add(p.date);
                }
            }
        }
        return dateByUserWroteMessage;
    }

    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Date> dateByUserDownloadPlugin = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.equals(Event.DOWNLOAD_PLUGIN.toString())) {
                    dateByUserDownloadPlugin.add(p.date);
                }
            }
        }
        return dateByUserDownloadPlugin;
    }

    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return getAllEvents(after, before).size();
    }

    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Event> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.LOGIN.toString())) {
                events.add(Event.LOGIN);
            } else if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                events.add(Event.DOWNLOAD_PLUGIN);
            } else if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                events.add(Event.WRITE_MESSAGE);
            } else if (p.event.contains(Event.SOLVE_TASK.toString())) {
                events.add(Event.SOLVE_TASK);
            } else if (p.event.contains(Event.DONE_TASK.toString())) {
                events.add(Event.DONE_TASK);
            }
        }
        return events;
    }

    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Event> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.ip.equals(ip)) {
                if (p.event.contains(Event.LOGIN.toString())) {
                    events.add(Event.LOGIN);
                } else if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                    events.add(Event.DOWNLOAD_PLUGIN);
                } else if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                    events.add(Event.WRITE_MESSAGE);
                } else if (p.event.contains(Event.SOLVE_TASK.toString())) {
                    events.add(Event.SOLVE_TASK);
                } else if (p.event.contains(Event.DONE_TASK.toString())) {
                    events.add(Event.DONE_TASK);
                }
            }
        }
        return events;
    }

    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Event> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.user.equals(user)) {
                if (p.event.contains(Event.LOGIN.toString())) {
                    events.add(Event.LOGIN);
                } else if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                    events.add(Event.DOWNLOAD_PLUGIN);
                } else if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                    events.add(Event.WRITE_MESSAGE);
                } else if (p.event.contains(Event.SOLVE_TASK.toString())) {
                    events.add(Event.SOLVE_TASK);
                } else if (p.event.contains(Event.DONE_TASK.toString())) {
                    events.add(Event.DONE_TASK);
                }
            }
        }
        return events;
    }

    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Event> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.status.equals(Status.FAILED.toString())) {
                if (p.event.contains(Event.LOGIN.toString())) {
                    events.add(Event.LOGIN);
                } else if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                    events.add(Event.DOWNLOAD_PLUGIN);
                } else if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                    events.add(Event.WRITE_MESSAGE);
                } else if (p.event.contains(Event.SOLVE_TASK.toString())) {
                    events.add(Event.SOLVE_TASK);
                } else if (p.event.contains(Event.DONE_TASK.toString())) {
                    events.add(Event.DONE_TASK);
                }
            }
        }
        return events;
    }

    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Event> events = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.status.equals(Status.ERROR.toString())) {
                if (p.event.contains(Event.LOGIN.toString())) {
                    events.add(Event.LOGIN);
                } else if (p.event.contains(Event.DOWNLOAD_PLUGIN.toString())) {
                    events.add(Event.DOWNLOAD_PLUGIN);
                } else if (p.event.contains(Event.WRITE_MESSAGE.toString())) {
                    events.add(Event.WRITE_MESSAGE);
                } else if (p.event.contains(Event.SOLVE_TASK.toString())) {
                    events.add(Event.SOLVE_TASK);
                } else if (p.event.contains(Event.DONE_TASK.toString())) {
                    events.add(Event.DONE_TASK);
                }
            }
        }
        return events;
    }

    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        int attemptCount = 0;
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.SOLVE_TASK.toString())) {
                if (p.event.contains(String.valueOf(task))) {
                    attemptCount++;
                }
            }
        }
        return attemptCount;
    }

    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        int attemptCount = 0;
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.DONE_TASK.toString())) {
                if (p.event.contains(String.valueOf(task))) {
                    attemptCount++;
                }
            }
        }
        return attemptCount;
    }

    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Map<Integer, Integer> map = new HashMap<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.SOLVE_TASK.toString())) {
                Integer taskNum = Integer.parseInt(p.event.split(" ")[1]);
                Integer attNum = map.get(taskNum);
                map.put(taskNum, attNum == null ? 1 : attNum + 1);
            }
        }
        return map;
    }

    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Map<Integer, Integer> map = new HashMap<>();
        for (Parser p :
                listPeriod) {
            if (p.event.contains(Event.DONE_TASK.toString())) {
                Integer taskNum = Integer.parseInt(p.event.split(" ")[1]);
                Integer attNum = map.get(taskNum);
                map.put(taskNum, attNum == null ? 1 : attNum + 1);
            }
        }
        return map;
    }

    @Override
    public Set execute(String query) {
        String[] parseQuery = null;
        if (!query.contains(" and date between ")) {
            parseQuery = query.split(" ", 6);
            if (parseQuery.length == 2) {
                switch (query) {
                    case "get ip":
                        return getUniqueIPs(null, null);
                    case "get user":
                        return getAllUsers();
                    case "get date":
                        return getAllDates();
                    case "get event":
                        return getAllEvents(null, null);
                    case "get status":
                        return getAllStatus(null, null);
                    default:
                        return null;
                }
            } else if (parseQuery.length == 6) {
                String field2 = parseQuery[3];
                String field1 = parseQuery[1];
                String value = parseQuery[5].substring(1, parseQuery[5].length() - 1);
                SimpleDateFormat sdf = new SimpleDateFormat("d.M.y H:m:s");
                List<Parser> list = Parser.parseLog(logDir);
                Set result = new HashSet();
                switch (field2) {
                    case "ip":
                        for (Parser p :
                                list) {
                            if (p.ip.equals(value)) {
                                switch (field1) {
                                    case "user":
                                        result.add(p.user);
                                        break;
                                    case "date":
                                        result.add(p.date);
                                        break;
                                    case "event":
                                        result.add(Event.valueOf(p.event.split(" ")[0]));
                                        break;
                                    case "status":
                                        result.add(Status.valueOf(p.status));
                                        break;
                                }
                            }
                        }
                        return result;
                    case "user":
                        for (Parser p :
                                list) {
                            if (p.user.equals(value)) {
                                switch (field1) {
                                    case "ip":
                                        result.add(p.ip);
                                        break;
                                    case "date":
                                        result.add(p.date);
                                        break;
                                    case "event":
                                        result.add(Event.valueOf(p.event.split(" ")[0]));
                                        break;
                                    case "status":
                                        result.add(Status.valueOf(p.status));
                                        break;
                                }
                            }
                        }
                        return result;

                    case "date":
                        for (Parser p :
                                list) {
                            try {
                                if (p.date.equals(sdf.parse(value))) {
                                    switch (field1) {
                                        case "ip":
                                            result.add(p.ip);
                                            break;
                                        case "user":
                                            result.add(p.user);
                                            break;
                                        case "event":
                                            result.add(Event.valueOf(p.event.split(" ")[0]));
                                            break;
                                        case "status":
                                            result.add(Status.valueOf(p.status));
                                            break;
                                    }
                                }
                            } catch (ParseException e) {
                            }
                        }
                        return result;

                    case "event":
                        for (Parser p :
                                list) {
                            if (p.event.contains(value)) {
                                switch (field1) {
                                    case "ip":
                                        result.add(p.ip);
                                        break;
                                    case "user":
                                        result.add(p.user);
                                        break;
                                    case "date":
                                        result.add(p.date);
                                        break;
                                    case "status":
                                        result.add(Status.valueOf(p.status));
                                        break;
                                }
                            }
                        }
                        return result;

                    case "status":
                        for (Parser p :
                                list) {
                            if (p.status.equals(value)) {
                                switch (field1) {
                                    case "ip":
                                        result.add(p.ip);
                                        break;
                                    case "user":
                                        result.add(p.user);
                                        break;
                                    case "date":
                                        result.add(p.date);
                                        break;
                                    case "event":
                                        result.add(Event.valueOf(p.event.split(" ")[0]));
                                        break;
                                }
                            }
                        }
                        return result;

                    default:
                        return result;
                }

            }
        } else{
            String[] dateSplit = query.split(" and date between ");
            parseQuery = dateSplit[0].split(" ", 6);
            String dA = dateSplit[1].split(" and ")[0];
            String dB = dateSplit[1].split(" and ")[1];
            String dateAfter = dA.substring(1, dA.length() - 1);
            String dateBefore = dB.substring(1, dB.length() - 1);
            String field2 = parseQuery[3];
            String field1 = parseQuery[1];
            String value = parseQuery[5].substring(1, parseQuery[5].length() - 1);
            SimpleDateFormat sdf = new SimpleDateFormat("d.M.y H:m:s");

            List<Parser> all = Parser.parseLog(logDir);
            List<Parser> list = null;
            try {
                list = Parser.getLogsFromToNotIncludeBounds(all, sdf.parse(dateAfter), sdf.parse(dateBefore));
            } catch (Exception e) {

            }
            Set result = new HashSet();
            switch (field2) {
                case "ip":
                    for (Parser p :
                            list) {
                        if (p.ip.equals(value)) {
                            switch (field1) {
                                case "user":
                                    result.add(p.user);
                                    break;
                                case "date":
                                    result.add(p.date);
                                    break;
                                case "event":
                                    result.add(Event.valueOf(p.event.split(" ")[0]));
                                    break;
                                case "status":
                                    result.add(Status.valueOf(p.status));
                                    break;
                            }
                        }
                    }
                    return result;
                case "user":
                    for (Parser p :
                            list) {
                        if (p.user.equals(value)) {
                            switch (field1) {
                                case "ip":
                                    result.add(p.ip);
                                    break;
                                case "date":
                                    result.add(p.date);
                                    break;
                                case "event":
                                    result.add(Event.valueOf(p.event.split(" ")[0]));
                                    break;
                                case "status":
                                    result.add(Status.valueOf(p.status));
                                    break;
                            }
                        }
                    }
                    return result;

                case "date":
                    for (Parser p :
                            list) {
                        try {
                            if (p.date.equals(sdf.parse(value))) {
                                switch (field1) {
                                    case "ip":
                                        result.add(p.ip);
                                        break;
                                    case "user":
                                        result.add(p.user);
                                        break;
                                    case "event":
                                        result.add(Event.valueOf(p.event.split(" ")[0]));
                                        break;
                                    case "status":
                                        result.add(Status.valueOf(p.status));
                                        break;
                                }
                            }
                        } catch (ParseException e) {
                        }
                    }
                    return result;

                case "event":
                    for (Parser p :
                            list) {
                        if (p.event.contains(value)) {
                            switch (field1) {
                                case "ip":
                                    result.add(p.ip);
                                    break;
                                case "user":
                                    result.add(p.user);
                                    break;
                                case "date":
                                    result.add(p.date);
                                    break;
                                case "status":
                                    result.add(Status.valueOf(p.status));
                                    break;
                            }
                        }
                    }
                    return result;

                case "status":
                    for (Parser p :
                            list) {
                        if (p.status.equals(value)) {
                            switch (field1) {
                                case "ip":
                                    result.add(p.ip);
                                    break;
                                case "user":
                                    result.add(p.user);
                                    break;
                                case "date":
                                    result.add(p.date);
                                    break;
                                case "event":
                                    result.add(Event.valueOf(p.event.split(" ")[0]));
                                    break;
                            }
                        }
                    }
                    return result;

                default:
                    return result;
            }

        }
        return null;
    }

    public Set<Status> getAllStatus(Date after, Date before) {
        List<Parser> userList = Parser.parseLog(logDir);
        List<Parser> listPeriod = Parser.getLogsFromTo(userList, after, before);
        Set<Status> statuses = new HashSet<>();
        for (Parser p :
                listPeriod) {
            if (p.status.equals(Status.OK.toString())) {
                statuses.add(Status.OK);
            } else if (p.status.equals(Status.FAILED.toString())) {
                statuses.add(Status.FAILED);
            } else if (p.status.equals(Status.ERROR.toString())) {
                statuses.add(Status.ERROR);
            }
        }
        return statuses;
    }

    public Set<Date> getAllDates() {
        List<Parser> userList = Parser.parseLog(logDir);
        Set<Date> dates = new HashSet<>();
        for (Parser p :
                userList) {
            dates.add(p.date);
        }
        return dates;
    }


    public static class Parser {
        private String ip;
        private String user;
        private Date date;
        private String event;
        private String status;

        public Parser(String ip, String user, Date date, String event, String status) {
            this.ip = ip;
            this.user = user;
            this.date = date;
            this.event = event;
            this.status = status;
        }

        public static List<Parser> parseLog(Path dir) {
            List<Parser> list = new ArrayList<>();
            SimpleDateFormat sdf = new SimpleDateFormat("d.M.y H:m:s");
            for (File f :
                    dir.toFile().listFiles()) {
                if (f.getAbsolutePath().endsWith(".log")) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(f))) {
                        while (reader.ready()) {
                            String read = reader.readLine();
                            String[] parse = read.split("\\t");
                            list.add(new Parser(parse[0], parse[1], sdf.parse(parse[2]), parse[3], parse[4]));
                        }
                    } catch (FileNotFoundException e) {
                        e.printStackTrace();
                    } catch (IOException e) {
                        e.printStackTrace();
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                }
            }
            return list;
        }

        public static List<Parser> getLogsFromTo(List<Parser> parsers, Date after, Date before) {
            List<Parser> result = new ArrayList<>();
            for (Parser p :
                    parsers) {
                if (after == null && before == null) {
                    result.add(p);
                } else if (after == null) {
                    if (p.date.equals(before) || p.date.before(before)) {
                        result.add(p);
                    }
                } else if (before == null) {
                    if (p.date.equals(after) || p.date.after(after)) {
                        result.add(p);
                    }
                } else {
                    if (p.date.equals(before) || p.date.before(before)) {
                        if (p.date.equals(after) || p.date.after(after)) {
                            result.add(p);
                        }
                    }
                }
            }
            return result;
        }

        public static List<Parser> getLogsFromToNotIncludeBounds(List<Parser> parsers, Date after, Date before) {
            List<Parser> result = new ArrayList<>();
            for (Parser p :
                    parsers) {
                if (after == null && before == null) {
                    result.add(p);
                } else if (after == null) {
                    if (p.date.before(before)) {
                        result.add(p);
                    }
                } else if (before == null) {
                    if (p.date.after(after)) {
                        result.add(p);
                    }
                } else {
                    if (p.date.before(before)) {
                        if (p.date.after(after)) {
                            result.add(p);
                        }
                    }
                }
            }
            return result;
        }
    }
}