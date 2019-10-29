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

create table edns_tests
(	
	id serial not null
		constraint edns_tests_pk
			primary key,
	exec_date date,
	ns varchar,
	dns_plain int,
	edns_plain int,
	edns_unknw int,
	edns_unknwopt int,
	edns_unknwflag int,
	edns_dnssec int,
	edns_trunc int,
	edns_unknwveropt int,
	edns_tcp int,
	ip_type varchar,
	insert_date timestamp default CURRENT_TIMESTAMP not null
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
	id serial not null
		constraint cctld_edns_tests_pk
			primary key,
	exec_date date,
	ns varchar,
	dns_plain int,
	edns_plain int,
	edns_unknw int,
	edns_unknwopt int,
	edns_unknwflag int,
	edns_dnssec int,
	edns_trunc int,
	edns_unknwveropt int,
	edns_tcp int,
	insert_date timestamp default CURRENT_TIMESTAMP not null
);

alter table cctld_edns_tests owner to ymk;

