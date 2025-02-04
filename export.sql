-- MySQL dump 10.13  Distrib 8.0.38, for Win64 (x86_64)
--
-- Host: localhost    Database: dashboard
-- ------------------------------------------------------
-- Server version	8.0.38

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `dast_vulns`
--

DROP TABLE IF EXISTS `dast_vulns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `dast_vulns` (
  `ria_id` varchar(500) NOT NULL,
  `total_vulns` varchar(500) NOT NULL,
  `vulns_unresolved` int NOT NULL,
  `vulns_unres_excl_low` int NOT NULL,
  `last_tested_date` date DEFAULT NULL,
  PRIMARY KEY (`ria_id`),
  CONSTRAINT `dast_vulns_ibfk_1` FOREIGN KEY (`ria_id`) REFERENCES `inventory` (`ria_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `dast_vulns`
--

LOCK TABLES `dast_vulns` WRITE;
/*!40000 ALTER TABLE `dast_vulns` DISABLE KEYS */;
INSERT INTO `dast_vulns` VALUES ('123','Total: 2| C: 1| H: 1| M: 0| L: 0',2,2,'2025-01-25'),('124','Total: 1| C: 0| H: 0| M: 0| L: 1',1,0,'2025-01-25');
/*!40000 ALTER TABLE `dast_vulns` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `inventory`
--

DROP TABLE IF EXISTS `inventory`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `inventory` (
  `ria_id` varchar(500) NOT NULL,
  `application_name` varchar(500) NOT NULL,
  `criticality` varchar(20) NOT NULL,
  `public_facing` varchar(10) NOT NULL,
  `cots` varchar(10) NOT NULL,
  `dast` varchar(10) NOT NULL,
  PRIMARY KEY (`ria_id`),
  UNIQUE KEY `application_name` (`application_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `inventory`
--

LOCK TABLES `inventory` WRITE;
/*!40000 ALTER TABLE `inventory` DISABLE KEYS */;
INSERT INTO `inventory` VALUES ('1','AU0101','Critical','YES','NO',''),('110','RIB','Critical','YES','NO',''),('111','Profile','Critical','NO','NO',''),('112','Cortex','Non-critical','YES','NO',''),('113','Memento','Non-critical','NO','NO',''),('114','MIS','Non-critical','NO','NO',''),('123','Test3','Critical','YES','NO','YES'),('124','Test4','Critical','YES','NO','YES'),('16','Mobile Banking','Critical','YES','NO',''),('2','BBPS','Critical','YES','NO',''),('3','CTS','Critical','NO','NO',''),('37','WSO2 (IDAM)','Critical','YES','NO',''),('ria00123','Test1','Critical','YES','YES',''),('ria00456','Test2','Non-critical','YES','YES',''),('RIA00747','AMS','Critical','NO','NO','');
/*!40000 ALTER TABLE `inventory` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `kri`
--

DROP TABLE IF EXISTS `kri`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `kri` (
  `question_no` varchar(100) NOT NULL,
  `question` text NOT NULL,
  `au_remarks` text,
  `fincare_remarks` text,
  `au_percent` decimal(10,0) DEFAULT NULL,
  `fincare_percent` decimal(10,0) DEFAULT NULL,
  `total_percent` decimal(10,0) DEFAULT NULL,
  `remarks` text,
  PRIMARY KEY (`question_no`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `kri`
--

LOCK TABLES `kri` WRITE;
/*!40000 ALTER TABLE `kri` DISABLE KEYS */;
INSERT INTO `kri` VALUES ('2.1.17','Percentage of [Number of open/outstanding findings from security assessments (VA/PT/AppSec) of critical applications pending beyond two months but up to six months to total number of observations from security assessments (VA/PT/AppSec) of critical applications in last six months]',NULL,NULL,75,NULL,NULL,'Open vulns of critical apps pending 2-6 months: 9. Total vulns of critical apps upto 6 months: 12'),('2.1.18','Percentage of [Number of open/outstanding findings from security assessments (VA/PT/AppSec) of critical applications pending beyond six months but up to 12 months to total number of observations from security assessments (VA/PT/AppSec) of critical applications in last 12 months]',NULL,NULL,27,NULL,NULL,'Open vulns of critical apps pending 6-12 months: 7. Total vulns of critical apps upto 12 months: 26'),('2.1.22','Percentage of [web applications not exposed in public domain that are not OWASP Top 10 compliant to total web applications not exposed in public domain in production environment]. For the purpose of this data point, exclude the low risk vulnerabilities.',NULL,NULL,60,NULL,NULL,'Non-compliant non-public facing applications: 3. Total non-public facing applications: 5'),('2.1.23','Percentage of [web applications that are exposed in public domain that are not OWASP Top 10 compliant (as assessed by the bank) to total web Applications that are exposed in public domain]. For the purpose of this data point, exclude the low risk vulnerabilities.',NULL,NULL,80,NULL,NULL,'Non-compliant public facing applications: 8. Total public facing applications: 10');
/*!40000 ALTER TABLE `kri` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vuln_tracker`
--

DROP TABLE IF EXISTS `vuln_tracker`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vuln_tracker` (
  `id` int NOT NULL AUTO_INCREMENT,
  `application_name` varchar(500) NOT NULL,
  `test_type` varchar(100) DEFAULT NULL,
  `vuln_name` varchar(500) NOT NULL,
  `jira_id` varchar(100) DEFAULT NULL,
  `reported_date` date NOT NULL,
  `ageing` int NOT NULL,
  `sla` int NOT NULL,
  `breach_status` varchar(100) NOT NULL,
  `severity` varchar(100) NOT NULL,
  `occurence` varchar(500) DEFAULT NULL,
  `vuln_status` varchar(100) NOT NULL,
  `closure_date` date DEFAULT NULL,
  `close_remarks` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `application_name` (`application_name`),
  CONSTRAINT `vuln_tracker_ibfk_1` FOREIGN KEY (`application_name`) REFERENCES `inventory` (`application_name`)
) ENGINE=InnoDB AUTO_INCREMENT=70 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vuln_tracker`
--

LOCK TABLES `vuln_tracker` WRITE;
/*!40000 ALTER TABLE `vuln_tracker` DISABLE KEYS */;
INSERT INTO `vuln_tracker` VALUES (1,'Mobile Banking','APK Prod','Excessive perms','','2024-10-01',116,30,'Breached','High','','Open',NULL,''),(2,'Mobile Banking','APK Prod','Exported set to true','','2024-09-05',142,60,'Breached','Medium','','Open',NULL,''),(3,'Mobile Banking','APK Prod','Root detection bypass','','2024-11-21',65,60,'Breached','Medium','','Open',NULL,''),(4,'Mobile Banking','APK Prod','SSL bypass','','2024-10-01',63,90,'Not-breached','Low','','Closed','2024-12-03',''),(5,'WSO2 (IDAM)','Web','Credentials in PT','','2024-07-01',208,30,'Breached','High','','Open',NULL,''),(6,'WSO2 (IDAM)','Web','SQL injection','','2024-11-01',6,15,'Not-breached','Critical','','Closed','2024-11-07',''),(7,'WSO2 (IDAM)','Web','Cross-site scriping','','2024-08-06',172,30,'Breached','High','','Open',NULL,''),(8,'WSO2 (IDAM)','Web','File upload bypass','','2024-10-01',116,60,'Breached','Medium','','Open',NULL,''),(9,'WSO2 (IDAM)','Web','Misconfigured cache control header','','2024-10-31',86,90,'Not-breached','Low','','Open',NULL,''),(10,'Test1','','Vuln1','','2025-01-01',24,60,'Not-breached','Medium','','Open',NULL,''),(11,'Test2','','Vuln1','','2024-10-01',116,30,'Breached','High','','Open',NULL,''),(12,'RIB','Web','xxxx','','2024-03-12',196,30,'Breached','High','','Closed','2024-09-24',''),(13,'RIB','','ccc','','2024-03-12',139,60,'Breached','Medium','','Closed','2024-07-29',''),(14,'Profile','','a','','2024-09-19',128,60,'Breached','Medium','','Open',NULL,''),(15,'Profile','','b','','2024-09-19',128,90,'Breached','Low','','Open',NULL,''),(16,'Profile','','c','','2024-09-19',128,90,'Breached','Low','','Open',NULL,''),(17,'Cortex','','a','','2024-07-12',96,30,'Breached','High','','Closed','2024-10-16',''),(18,'Cortex','','b','','2024-07-12',145,90,'Breached','Low','','Closed','2024-12-04',''),(19,'Cortex','','c','','2024-07-12',61,15,'Breached','Critical','','Closed','2024-09-11',''),(20,'Cortex','','d','','2024-07-12',117,90,'Breached','Low','','Closed','2024-11-06',''),(21,'Cortex','','e','','2024-07-12',11,15,'Not-breached','Critical','','Closed','2024-07-23',''),(22,'Memento','','a','','2023-08-04',466,60,'Breached','Medium','','Closed','2024-11-12',''),(23,'Memento','','b','','2023-08-04',396,30,'Breached','High','','Closed','2024-09-03',''),(24,'MIS','','a','','2023-09-19',494,90,'Breached','Low','','Open',NULL,''),(25,'MIS','','b','','2023-09-19',494,60,'Breached','Medium','','Open',NULL,''),(26,'AU0101','','Vuln1','','2024-04-02',274,30,'Breached','High','','Closed','2025-01-01',''),(27,'AU0101','','Vuln2','','2024-04-02',298,30,'Breached','High','','Open',NULL,''),(28,'AU0101','','Vuln3','','2024-04-02',274,60,'Breached','Medium','','Closed','2025-01-01',''),(29,'AU0101','','Vuln4','','2024-04-02',298,60,'Breached','Medium','','Open',NULL,''),(30,'BBPS','','Vuln1','','2024-03-21',286,60,'Breached','Medium','','Closed','2025-01-01',''),(31,'BBPS','','Vuln2','','2024-03-21',310,60,'Breached','Medium','','Open',NULL,''),(32,'BBPS','','Vuln3','','2024-03-21',286,60,'Breached','Medium','','Closed','2025-01-01',''),(33,'BBPS','','Vuln4','','2024-03-21',310,90,'Breached','Low','','Open',NULL,''),(34,'CTS','','Vuln1','','2024-03-11',296,30,'Breached','High','','Closed','2025-01-01',''),(35,'CTS','','Vuln2','','2024-03-11',320,60,'Breached','Medium','','Open',NULL,''),(36,'CTS','','Vuln3','','2024-03-11',320,90,'Breached','Low','','Open',NULL,''),(37,'CTS','','Vuln4','','2024-03-11',320,90,'Breached','Low','','Open',NULL,''),(64,'Test3','DAST','Vuln1','','2025-01-01',24,15,'Breached','Critical','','Open',NULL,''),(65,'Test4','','Vuln1','','2025-01-01',24,30,'Not-breached','High','','Open',NULL,''),(66,'Test3','','Vuln2','','2025-01-01',24,60,'Not-breached','Medium','','Open',NULL,''),(67,'Test4','DAST','Vuln1','','2025-01-01',24,90,'Not-breached','Low','','Open',NULL,''),(68,'Test3','DAST','Vuln3','','2025-01-01',24,30,'Not-breached','High','','Open',NULL,''),(69,'Test4','','Vuln3','','2025-01-01',24,90,'Not-breached','Low','','Open',NULL,'');
/*!40000 ALTER TABLE `vuln_tracker` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `vulns`
--

DROP TABLE IF EXISTS `vulns`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vulns` (
  `ria_id` varchar(500) NOT NULL,
  `total_vulns` varchar(500) NOT NULL,
  `vulns_unresolved` int NOT NULL,
  `vulns_unres_excl_low` int NOT NULL,
  `last_tested_date` date DEFAULT NULL,
  PRIMARY KEY (`ria_id`),
  CONSTRAINT `vulns_ibfk_1` FOREIGN KEY (`ria_id`) REFERENCES `inventory` (`ria_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vulns`
--

LOCK TABLES `vulns` WRITE;
/*!40000 ALTER TABLE `vulns` DISABLE KEYS */;
INSERT INTO `vulns` VALUES ('1','Total: 4| C: 0| H: 2| M: 2| L: 0',2,2,'2025-01-23'),('110','Total: 2| C: 0| H: 1| M: 1| L: 0',0,0,'2025-01-21'),('111','Total: 3| C: 0| H: 0| M: 1| L: 2',3,1,'2025-01-21'),('112','Total: 5| C: 2| H: 1| M: 0| L: 2',0,0,'2025-01-21'),('113','Total: 2| C: 0| H: 1| M: 1| L: 0',0,0,'2025-01-21'),('114','Total: 2| C: 0| H: 0| M: 1| L: 1',2,1,'2025-01-21'),('123','Total: 1| C: 0| H: 0| M: 1| L: 0',1,1,'2025-01-25'),('124','Total: 2| C: 0| H: 1| M: 0| L: 1',2,1,'2025-01-25'),('16','Total: 4| C: 0| H: 1| M: 2| L: 1',3,3,NULL),('2','Total: 4| C: 0| H: 0| M: 3| L: 1',2,1,'2025-01-23'),('3','Total: 4| C: 0| H: 1| M: 1| L: 2',3,1,'2025-01-23'),('37','Total: 5| C: 1| H: 2| M: 1| L: 1',4,3,NULL),('ria00123','Total: 1| C: 0| H: 0| M: 1| L: 0',1,1,'2025-01-21'),('ria00456','Total: 1| C: 0| H: 1| M: 0| L: 0',1,1,'2025-01-21');
/*!40000 ALTER TABLE `vulns` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-01-27  9:07:51
