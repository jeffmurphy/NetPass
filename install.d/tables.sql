
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
	message         TEXT,
	username	VARCHAR(16)  NOT NULL,
	OS		VARCHAR(255),
	switchIP	VARCHAR(128),
	switchPort	SMALLINT,

	PRIMARY KEY(macAddress)
) TYPE=NDBCLUSTER;

CREATE TABLE results (
	macAddress	VARCHAR(32)	NOT NULL,
	dt		DATETIME	NOT NULL,
	testType	VARCHAR(32),    #enum('nessus', 'snort', 'manual')  NOT NULL,
	ID		VARCHAR(128),
	status		enum('pending', 'user-fixed', 'fixed') NOT NULL default 'pending',
	INDEX (macAddress),
	INDEX (macAddress, testType),
	INDEX (macAddress, status),
) TYPE=NDBCLUSTER;

CREATE TABLE policy (
	name		VARCHAR(128) NOT NULL,
	val		VARCHAR(128) NOT NULL,
	PRIMARY KEY(name)
) TYPE=NDBCLUSTER;

CREATE TABLE users (
	username	VARCHAR(128) NOT NULL,
	groups          VARCHAR(128) NOT NULL,
	PRIMARY KEY (username)
) TYPE=NDBCLUSTER;

reate table config (
	rev	integer unsigned not null auto_increment,
	dt	datetime not null,
	xlock   integer not null default 0,
	user	varchar(128) not null,
	log     text,
	config	text,
	primary key (rev),
	index (dt)
) type=ndbcluster;

CREATE TABLE passwd (
	username	VARCHAR(128) NOT NULL,
	password	VARCHAR(128),
	PRIMARY KEY(username)
) TYPE=NDBCLUSTER;

INSERT INTO users VALUES ('netpass', 'default+Admin');
INSERT INTO passwd VALUES ('netpass', ENCRYPT('netpass', 'xx'));
	
CREATE TABLE pages (
	network         VARCHAR(128) NOT NULL default 'default',
	name		VARCHAR(128) NOT NULL,
	content		TEXT,
	UNIQUE INDEX (name, network)
) TYPE=NDBCLUSTER;


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
) TYPE=NDBCLUSTER;

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
) TYPE=NDBCLUSTER;

CREATE TABLE clientHistory (
	macAddress      VARCHAR(32)	NOT NULL,
	username        VARCHAR(32)	NOT NULL,
	dt		DATETIME	NOT NULL,
	notes		TEXT		NOT NULL,
	INDEX(macAddress),
	INDEX(dt)
) TYPE=NDBCLUSTER;

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
) TYPE=NDBCLUSTER;

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
) TYPE=NDBCLUSTER;

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
) TYPE=NDBCLUSTER;

CREATE TABLE stats_procs (
  `serverid` varchar(128) NOT NULL,
  `dt` datetime NOT NULL,
  `proc` varchar(128) NOT NULL,
  `count` integer NOT NULL,
  INDEX(dt),
  INDEX(proc)
) TYPE=NDBCLUSTER;

CREATE TABLE urlFilters (
	url	varchar(254) not null,
	dst	varchar(254),
	network varchar(128) not null,
	action  enum('permit', 'soft-redirect', 'hard-redirect', 'block') not null,
	unique index (url, network)
);


insert into urlFilters values ('itpolicies\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values ('netpass\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values ('cert\.org', NULL, 'default', 'permit');
insert into urlFilters values ('download\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('lavasoftusa\.com', NULL, 'default', 'permit');
insert into urlFilters values ('microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('protect\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('redhat\.com', NULL, 'default', 'permit');
insert into urlFilters values ('securityresponse\.symantec\.com', NULL, 'default', 'permit');
insert into urlFilters values ('service1\.symantec\.com', NULL, 'default', 'permit');
insert into urlFilters values ('support\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('swquery\.apple\.com', NULL, 'default', 'permit');
insert into urlFilters values ('swscan\.apple\.com', NULL, 'default', 'permit');
insert into urlFilters values ('symantecliveupdate\.com', NULL, 'default', 'permit');
insert into urlFilters values ('us\.mcafee\.com', NULL, 'default', 'permit');
insert into urlFilters values ('vil\.nai\.com', NULL, 'default', 'permit');
insert into urlFilters values ('windows\.com', NULL, 'default', 'permit');
insert into urlFilters values ('windowsupdate\.com', NULL, 'default', 'permit');
insert into urlFilters values ('windowsupdate\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('wings\.buffalo\.edu', NULL, 'default', 'permit');
insert into urlFilters values ('www\.microsoft\.com', NULL, 'default', 'permit');
insert into urlFilters values ('www\.sans\.org', NULL, 'default', 'permit');
insert into urlFilters values ('www\.sophos\.com', NULL, 'default', 'permit');


insert into urlFilters values ('command\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values ('isapi60\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values ('wisapidata\.weatherbug\.com', NULL, 'default', 'block');
insert into urlFilters values ('config\.180solutions\.com', NULL, 'default', 'block');
insert into urlFilters values ('ping\.180solutions\.com', NULL, 'default', 'block');
insert into urlFilters values ('desktop3\.weather\.com', NULL, 'default', 'block');
insert into urlFilters values ('image\.weather\.com', NULL, 'default', 'block');
insert into urlFilters values ('www\.statblaster\.com/updatestats', NULL, 'default', 'block');
insert into urlFilters values ('www\.mydailyhoroscope\.net/mdh/AdResponse\.aspx', NULL, 'default','block');
insert into urlFilters values ('204\.177\.92\.204/w/getclientid', NULL, 'default', 'block');
insert into urlFilters values ('client\.warez\.com/data/gcache\.php', NULL, 'default', 'block');
insert into urlFilters values ('http://sports\.espn\.go\.com/espn/espnmotion/ESPNMotionXMLv4', NULL, 'default', 'block');

insert into urlFilters values ('DEFAULT', 'http://npvip-d.cit.buffalo.edu/?url=%u', 'default', 'hard-redirect');
