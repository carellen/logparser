package parserpac;

import java.nio.file.Paths;
import java.util.Date;

public class Solution {
    public static void main(String[] args) {
        LogParser logParser = new LogParser(Paths.get("C:\\Users\\vladimir\\IdeaProjects\\logParser\\src\\parserpac\\logs"));
        System.out.println(logParser.getUniqueIPs(null, new Date()));
        System.out.println("Уникальных Ip: " + logParser.getNumberOfUniqueIPs(null, new Date()));
        System.out.println(logParser.getIPsForUser("Alex", null, new Date()));
        System.out.println(logParser.getIPsForEvent(Event.SOLVE_TASK,null, new Date()));
        System.out.println(logParser.getIPsForStatus(Status.OK,null, new Date()));
        System.out.println(logParser.execute("get event for date = «30.01.2014 12:56:22»"));
        System.out.println(logParser.execute("get ip for user = \"Eduard Petrovich Morozko\" and date between \"11.12.2013 0:00:00\" and \"03.01.2014 23:59:59\""));

    }
}
