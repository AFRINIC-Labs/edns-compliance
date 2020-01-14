-- Afrinic Tables
create table edns_reverse
(
	id serial not null
		constraint edns_reverse_pk
			primary key,
	exec_date date,
	reverse_ns varchar not null,
	ns_type varchar not null,
	nameserver varchar not null,
	ip_type varchar,
	insert_date timestamp default CURRENT_TIMESTAMP not null
);

alter table edns_reverse owner to ymk;

create table ns_resolution
(
	id serial not null
		constraint ns_resolution_pk
			primary key,
	exec_date date,
	name_server varchar not null,
	ns_ip varchar not null,
	ns_ipv6 varchar,
	asnv4 varchar,
	asnv6 varchar,
	ccv4 varchar,
	ccv6 varchar,
	ip_type varchar,
	insert_date timestamp default CURRENT_TIMESTAMP not null
);

alter table ns_resolution owner to ymk;

CREATE TABLE edns_tests
(
	id serial NOT NULL,
	exec_date date NULL,
	ns varchar NULL,
	"zone" varchar NULL,
	dns_plain varchar NULL,
	edns_plain varchar NULL,
	edns_unknw varchar NULL,
	edns_unknwopt varchar NULL,
	edns_unknwflag varchar NULL,
	edns_dnssec varchar NULL,
	edns_trunc varchar NULL,
	edns_unknwveropt varchar NULL,
	edns_tcp varchar NULL,
	packet_size numeric NULL,
	f_edns_no_tcp varchar NULL,
	f_edns_tcp varchar NULL,
	f_packet_size varchar NULL,
	ip_type varchar NULL,
	insert_date timestamp default CURRENT_TIMESTAMP not null
	absolute_compliant varchar NULL,
	CONSTRAINT edns_tests_pk PRIMARY KEY (id)
);

alter table edns_tests owner to ymk;


-- ccTLD tables
create table cctld_ns_resolution
(
	id serial not null
		constraint cctld_ns_resolution_pk
			primary key,
	exec_date date,
	countrycode varchar not null,
	name_server varchar not null,
	ns_ip varchar not null,
	ns_ipv6 varchar,
	asnv4 varchar,
	asnv6 varchar,
	ccv4 varchar,
	ccv6 varchar,
	insert_date timestamp default CURRENT_TIMESTAMP not null
);

alter table cctld_ns_resolution owner to ymk;

create table cctld_edns_tests
(
	id serial NOT NULL,
	exec_date date NULL,
	ns varchar NULL,
	"zone" varchar NULL,
	dns_plain varchar NULL,
	edns_plain varchar NULL,
	edns_unknw varchar NULL,
	edns_unknwopt varchar NULL,
	edns_unknwflag varchar NULL,
	edns_dnssec varchar NULL,
	edns_trunc varchar NULL,
	edns_unknwveropt varchar NULL,
	edns_tcp varchar NULL,
	packet_size numeric NULL,
	f_edns_no_tcp varchar NULL,
	f_edns_tcp varchar NULL,
	f_packet_size varchar NULL,
	ip_type varchar NULL,
	insert_date timestamp default CURRENT_TIMESTAMP not null
	absolute_compliant varchar NULL,
	CONSTRAINT edns_tests_pk PRIMARY KEY (id)
);

alter table cctld_edns_tests owner to ymk;

