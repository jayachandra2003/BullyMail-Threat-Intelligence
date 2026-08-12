/*
BullyMail V2 Database Setup Script
MySQL 8.0 / 5.7+ Compatible Database Initialization
Character Set: utf8mb4 (Full Unicode & Emoji Support)
*/

CREATE DATABASE IF NOT EXISTS `bullymail_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `bullymail_db`;

-- --------------------------------------------------------
-- Table structure for table `users`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(20) DEFAULT 'admin',
  `email` varchar(100) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Initial Administrator Account is provisioned securely upon first application startup
-- using the environment variables ADMIN_USERNAME and ADMIN_PASSWORD.

-- --------------------------------------------------------
-- Table structure for table `analyzed_emails` (Unified Multi-Vector Threats)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `analyzed_emails` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email_subject` text,
  `email_from` varchar(255) DEFAULT NULL,
  `email_to` varchar(255) DEFAULT NULL,
  `email_text` mediumtext NOT NULL,
  
  -- Overall Unified Threat Assessment
  `overall_risk_level` varchar(20) NOT NULL DEFAULT 'LOW',
  `overall_confidence` float NOT NULL DEFAULT '0',
  `threat_score` float NOT NULL DEFAULT '0',
  
  -- Cyberbullying Vector
  `is_bullying` tinyint(1) NOT NULL DEFAULT '0',
  `confidence` float NOT NULL DEFAULT '0',
  `rule_based_matches` text,
  `rule_based_score` float DEFAULT '0',
  `ml_prediction` tinyint(1) DEFAULT '0',
  `ml_confidence` float DEFAULT '0',
  `model_used` varchar(50) DEFAULT 'Hybrid',
  
  -- Phishing Vector
  `phishing_risk_level` varchar(20) DEFAULT 'LOW',
  `phishing_confidence` float DEFAULT '0',
  `phishing_indicators` mediumtext,
  
  -- Link & URL Vector
  `urls_detected` int(11) DEFAULT '0',
  `suspicious_urls_count` int(11) DEFAULT '0',
  `url_analysis_summary` mediumtext,
  
  -- Look-Alike Domain Vector
  `domain_analysis_summary` mediumtext,
  
  -- Social Engineering Vector
  `social_eng_risk_level` varchar(20) DEFAULT 'LOW',
  `social_eng_confidence` float DEFAULT '0',
  `social_eng_techniques` mediumtext,
  
  -- Attachment & Malware Vector
  `attachments_count` int(11) DEFAULT '0',
  `malware_risk_level` varchar(20) DEFAULT 'LOW',
  `attachment_analysis_summary` mediumtext,
  
  -- Image Forensics Vector
  `images_count` int(11) DEFAULT '0',
  `image_risk_level` varchar(20) DEFAULT 'LOW',
  `image_analysis_summary` mediumtext,
  
  -- Explainable Evidence
  `evidence_summary` mediumtext,
  
  `email_date` timestamp NULL DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_risk_level` (`overall_risk_level`),
  KEY `idx_is_bullying` (`is_bullying`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `model_history`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `model_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `model_type` varchar(50) NOT NULL,
  `precision_score` float DEFAULT '0',
  `recall_score` float DEFAULT '0',
  `f1_score` float DEFAULT '0',
  `accuracy` float DEFAULT '0',
  `confusion_matrix` text,
  `training_samples` int(11) DEFAULT '0',
  `test_samples` int(11) DEFAULT '0',
  `evaluation_type` varchar(50) DEFAULT 'Synthetic Evaluation',
  `dataset_used` varchar(255) DEFAULT 'default_academic_dataset',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `dataset_history`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `dataset_history` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `filename` varchar(255) NOT NULL,
  `total_samples` int(11) DEFAULT '0',
  `bullying_samples` int(11) DEFAULT '0',
  `non_bullying_samples` int(11) DEFAULT '0',
  `neutral_samples` int(11) DEFAULT '0',
  `file_size` varchar(50) DEFAULT '0 MB',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------
-- Table structure for table `email_config`
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS `email_config` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email_address` varchar(255) DEFAULT NULL,
  `configured_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `status` varchar(50) DEFAULT 'inactive',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
