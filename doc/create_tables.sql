
/* possibilities for 'status' 
        - quarantined temporarily until they pass checks
        - quarantined permenantly until someone manually intervenes
        - unquarantined (user has passed checks)
	- unquarantined permanently (administrative override)
*/

CREATE TABLE register (
	macAddress	CHAR(12)     NOT NULL,
	ipAddress       VARCHAR(64)  NOT NULL,
	firstSeen	DATETIME     NOT NULL,
	registeredOn	DATETIME,
	status          ENUM('QUAR', 'PQUAR', 'UNQUAR', 'PUNQUAR') NOT NULL,
	uqlinkup        ENUM('yes', 'no') NOT NULL DEFAULT 'no',
	message         TEXT,
	username	VARCHAR(16)  NOT NULL,
	OS		VARCHAR(255),
	switchIP	VARCHAR(128),
	switchPort	SMALLINT,

	PRIMARY KEY(macAddress)
) TYPE=INNODB;

CREATE TABLE results (
	macAddress	BIGINT		NOT NULL,
	dt		DATETIME	NOT NULL,
	testType	enum('nessus', 'snort', 'manual')  NOT NULL default 'nessus',
	nessusID	INTEGER UNSIGNED,
	snortID         INTEGER UNSIGNED,
	messageID	VARCHAR(128),
	status		enum('pending', 'user-fixed', 'fixed') NOT NULL default 'pending',
	PRIMARY KEY (macAddress)
) TYPE=INNODB;

CREATE TABLE policy (
	name		VARCHAR(128) NOT NULL,
	val		VARCHAR(128) NOT NULL,
	PRIMARY KEY(name)
) TYPE=INNODB;

CREATE TABLE users (
	username	VARCHAR(128) NOT NULL,
	groups          VARCHAR(128) NOT NULL,
	PRIMARY KEY(username)
) TYPE=INNODB;
	
CREATE TABLE pages (
	name		VARCHAR(128) NOT NULL,
	content		TEXT,
	PRIMARY KEY(name)
) TYPE=INNODB;


CREATE TABLE portMoves (
	serverid	VARCHAR(128)     NOT NULL,
	rowid           INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
	requested	DATETIME         NOT NULL,
	requestedBy     VARCHAR(128),
	switchIP	VARCHAR(128)     NOT NULL,
	switchPort	SMALLINT 	 NOT NULL,
	vlanId          ENUM('quarantine', 'unquarantine') NOT NULL,
	status		ENUM('pending', 'completed', 'unmanaged') NOT NULL DEFAULT 'pending',

	UNIQUE (serverid, rowid), /* the order is important here */
	INDEX (status),            /* we often query on status    */
        INDEX (requested),
        INDEX (switchIP, switchPort)
) TYPE=MyISAM;

CREATE TABLE audit (
	ts		DATETIME           NOT NULL,
	server          VARCHAR(128),
	username	VARCHAR(32),
	ipAddress	VARCHAR(64),
	macAddress	VARCHAR(12),
	severity	ENUM('DEBUG', 'ALERT', 'CRITICAL', 'ERROR',
			     'WARNING', 'NOTICE', 'INFO') 
                                            NOT NULL,
	location	VARCHAR(255),
	message		text	    NOT NULL,

	INDEX (username(8)),
	INDEX (ipAddress),
	INDEX (macAddress),
	INDEX (ts),
	FULLTEXT(message)
) TYPE=MyISAM;


CREATE TABLE `nessusScans` (
  `pluginID` int(10) unsigned NOT NULL default '0',
  `name` varchar(255) default NULL,
  `family` varchar(255) default NULL,
  `category` varchar(255) default NULL,
  `short_desc` varchar(255) default NULL,
  `description` text,
  `addedBy` varchar(32) NOT NULL default '',
  `addedOn` timestamp(14) NOT NULL,
  `lastModifiedBy` varchar(32) NOT NULL default '',
  `lastModifiedOn` timestamp(14) NOT NULL,
  `status` enum('enabled','disabled') default 'disabled',
  `info` varchar(255) NOT NULL default 'nessus:',
  `revision` varchar(255) default NULL,
  `copyright` varchar(255) default NULL,
  `cve` varchar(255) default NULL,
  `bugtraq` varchar(255) default NULL,
  `other_refs` varchar(255) default NULL,
  PRIMARY KEY  (`pluginID`),
  KEY `status` (`status`)
) TYPE=INNODB;

#		ENUM('httpd', 'nessusd', 'garp', 'squid', 'resetport', 
#				'portmover', 'macscan', 'netpass', 'npcfgd', 
#				'npstatusd', 'npsnortctl', 'npsnortd', 'unquar-all',
#				'quar-all'),

CREATE TABLE appStarter (
	rowid		INTEGER UNSIGNED AUTO_INCREMENT,
	requested	DATETIME,
	application	VARCHAR(64),
	action		ENUM('start', 'stop', 'restart'),
	actionAs        VARCHAR(16),
	status		ENUM('pending', 'completed'),
	PRIMARY KEY (rowid),
	INDEX (status)
) TYPE=INNODB;

# for Apache::Session

use sessions;

CREATE TABLE `sessions` (
  `id` varchar(64) NOT NULL,
  `length` int(11) default NULL,
  `a_session` text,
	PRIMARY KEY (id)
) TYPE=INNODB;

CREATE TABLE stats_procs (
  `serverid` varchar(128) NOT NULL,
  `dt` datetime NOT NULL,
  `proc` varchar(128) NOT NULL,
  `count` integer NOT NULL,
  INDEX(dt),
  INDEX(proc)
) TYPE=INNODB;
