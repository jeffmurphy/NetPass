
/* possibilities for 'status' 
        - quarantined temporarily until they pass checks
        - quarantined permenantly until someone manually intervenes
        - unquarantined (user has passed checks)
	- unquarantined permanently (administrative override)
*/

CREATE TABLE register (
	macAddress	VARCHAR(32)  NOT NULL,
	ipAddress       VARCHAR(64)  NOT NULL,
	lastSeen	DATETIME     NOT NULL,
	registeredOn	DATETIME,
	status          ENUM('QUAR', 'PQUAR', 'UNQUAR', 'PUNQUAR') NOT NULL,
	uqlinkup        ENUM('yes', 'no') NOT NULL DEFAULT 'no',
	username	VARCHAR(16)  NOT NULL,
	OS		VARCHAR(255),
	switchIP	VARCHAR(128),
	switchPort	SMALLINT,

	PRIMARY KEY(macAddress)
) ENGINE=NDBCLUSTER;

CREATE TABLE results (
	rowid           INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
	macAddress	VARCHAR(32)	NOT NULL,
	dt		DATETIME	NOT NULL,
	testType	VARCHAR(32),    #enum('nessus', 'snort', 'manual')  NOT NULL,
	ID		VARCHAR(128),
	status		enum('pending', 'user-fixed', 'fixed') NOT NULL default 'pending',
	PRIMARY KEY(rowid)
) ENGINE=NDBCLUSTER;

CREATE INDEX results_idx1 ON results (macAddress);
CREATE INDEX results_idx2 ON results (macAddress, testType);
CREATE INDEX results_idx3 ON results (macAddress, status);

CREATE TABLE policy (
	name		VARCHAR(128) NOT NULL,
	val		VARCHAR(128) NOT NULL,
	PRIMARY KEY(name)
) ENGINE=NDBCLUSTER;

CREATE TABLE users (
	username	VARCHAR(128) NOT NULL,
	groups          VARCHAR(128) NOT NULL,
	PRIMARY KEY (username)
) ENGINE=NDBCLUSTER;

CREATE TABLE config (
	rev	integer unsigned not null auto_increment,
	dt	datetime not null,
	xlock   integer not null default 0,
	user	varchar(128) not null,
	log     text,
	config	text,
	PRIMARY KEY (rev)
) type=ndbcluster;

CREATE INDEX config_idx1 ON config (dt);

CREATE TABLE passwd (
	username	VARCHAR(128) NOT NULL,
	password	VARCHAR(128),
	PRIMARY KEY(username)
) ENGINE=NDBCLUSTER;

INSERT INTO users VALUES ('netpass', 'default+Admin');
INSERT INTO passwd VALUES ('netpass', ENCRYPT('netpass', 'xx'));
	
CREATE TABLE pages (
	rowid		INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
	network         VARCHAR(128) NOT NULL default 'default',
	name		VARCHAR(128) NOT NULL,
	content		TEXT,
	PRIMARY KEY (rowid)
) ENGINE=NDBCLUSTER;

CREATE UNIQUE INDEX pages_idx1 ON pages (name, network);

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
) ENGINE=MyISAM;

CREATE TABLE audit (
	ts		DATETIME           NOT NULL,
	server          VARCHAR(128),
	username	VARCHAR(32),
	ipAddress	VARCHAR(64),
	macAddress	VARCHAR(32),
	severity	ENUM('DEBUG', 'ALERT', 'CRITICAL', 'ERROR',
			     'WARNING', 'NOTICE', 'INFO') 
                                            NOT NULL,
	location	VARCHAR(255),
	message		text	    NOT NULL,

	INDEX (username(8)),
	INDEX (ipAddress),
	INDEX (macAddress(12)),
	INDEX (ts)
) ENGINE=MyISAM;

CREATE TABLE clientHistory (
	rowid		INTEGER UNSIGNED AUTO_INCREMENT NOT NULL,
	macAddress      VARCHAR(32)	NOT NULL,
	username        VARCHAR(32)	NOT NULL,
	dt		DATETIME	NOT NULL,
	notes		TEXT		NOT NULL,
	PRIMARY KEY (rowid)
) ENGINE=NDBCLUSTER;

CREATE TABLE sideLinks (
        name	        VARCHAR(24)     NOT NULL,
        url             VARCHAR(255)     NOT NULL,
        PRIMARY KEY (name)
) ENGINE=NDBCLUSTER;

CREATE INDEX clientHistory_idx1 ON clientHistory (macAddress);
CREATE INDEX clientHistory_idx2 ON clientHistory (dt);

CREATE TABLE nessusScans (
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
  PRIMARY KEY  (`pluginID`)
) ENGINE=NDBCLUSTER;

CREATE INDEX nessusScans_idx1 ON nessusScans (status);

CREATE TABLE `snortRules` (
  `snortID` int(10) unsigned NOT NULL default '0',
  `name` varchar(255) default NULL,
  `category` varchar(255) default NULL,
  `classtype` varchar(64) default NULL,
  `short_desc` varchar(255) default NULL,
  `description` text,
  `rule` text,
  `addedBy` varchar(32) NOT NULL default '',
  `addedOn` timestamp(14) NOT NULL,
  `lastModifiedBy` varchar(32) NOT NULL default '',
  `lastModifiedOn` timestamp(14) NOT NULL,
  `status` enum('enabled','disabled') default 'disabled',
  `info` varchar(255) NOT NULL default 'snort:',
  `revision` varchar(255) default NULL,
  `other_refs` varchar(255) default NULL,
  PRIMARY KEY  (`snortID`),
  KEY `status` (`status`)
) ENGINE=NDBCLUSTER;

CREATE INDEX snortRules_idx1 ON snortRules (status);

CREATE TABLE testConfig (
	rowid		INTEGER UNSIGNED NOT NULL AUTO_INCREMENT,
	testType	VARCHAR(32) NOT NULL,
	ID		VARCHAR(128) NOT NULL,
	status		enum('enabled', 'disabled') NOT NULL default 'disabled',
	network         VARCHAR(128) NOT NULL default 'default',
	PRIMARY KEY (rowid)
) ENGINE=NDBCLUSTER;

CREATE INDEX testConfig_idx1 ON testConfig (testType, ID, status, network);
	
CREATE TABLE appStarter (
	rowid		INTEGER UNSIGNED AUTO_INCREMENT,
	requested	DATETIME,
	application	VARCHAR(64),
	action		ENUM('start', 'stop', 'restart'),
	actionAs        VARCHAR(16),
	status		ENUM('pending', 'completed'),
	PRIMARY KEY (rowid)
) ENGINE=NDBCLUSTER;

CREATE INDEX appStarter_idx1 ON appStarter (status);

CREATE TABLE stats_procs (
	rowid	INTEGER UNSIGNED AUTO_INCREMENT,
  `serverid` varchar(128) NOT NULL,
  `dt` datetime NOT NULL,
  `proc` varchar(128) NOT NULL,
  `count` integer NOT NULL,
  PRIMARY KEY (rowid)
) ENGINE=NDBCLUSTER;

CREATE INDEX stats_procs_idx1 ON stats_procs (dt);
CREATE INDEX stats_procs_idx2 ON stats_procs (proc);

CREATE TABLE urlFilters (
	rowid    INTEGER UNSIGNED AUTO_INCREMENT,
	url	varchar(254) not null,
	dst	varchar(254),
	network varchar(128) not null,
	action  enum('permit', 'soft-redirect', 'hard-redirect', 'block') not null,
	PRIMARY KEY (rowid)
);

CREATE UNIQUE INDEX urlFilters_idx1 ON urlFilters (url, network);


insert into urlFilters values (NULL,'itpolicies\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'netpass\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'cert\.org', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'download\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'lavasoftusa\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'protect\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'redhat\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'securityresponse\.symantec\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'service1\.symantec\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'support\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'swquery\.apple\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'swscan\.apple\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'symantecliveupdate\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'us\.mcafee\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'vil\.nai\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'windows\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'windowsupdate\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'windowsupdate\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'wings\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'www\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'www\.sans\.org', NULL, 'default', 'permit');
insert into urlFilters values (NULL,'www\.sophos\.com', NULL, 'default', 'permit');


insert into urlFilters values (NULL,'command\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'isapi60\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'wisapidata\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'config\.180solutions\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'ping\.180solutions\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'desktop3\.weather\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'image\.weather\.com', NULL, 'default', 'block');
insert into urlFilters values (NULL,'www\.statblaster\.com/updatestats', NULL, 'default', 'block');
insert into urlFilters values (NULL,'www\.mydailyhoroscope\.net/mdh/AdResponse\.aspx', NULL, 'default','block');
insert into urlFilters values (NULL,'204\.177\.92\.204/w/getclientid', NULL, 'default', 'block');
insert into urlFilters values (NULL,'client\.warez\.com/data/gcache\.php', NULL, 'default', 'block');
insert into urlFilters values (NULL,'http://sports\.espn\.go\.com/espn/espnmotion/ESPNMotionXMLv4', NULL, 'default', 'block');

insert into urlFilters values (NULL,'DEFAULT', 'http://npvip-d.cit.buffalo.edu/?url=%u', 'default', 'hard-redirect');
