-- Afrinic Tables
create table edns_reverse
(
	id serial not null
		constraint edns_reverse2_pkey
			primary key,
	reverse_ns varchar(255) not null,
	ns_type varchar(255) not null,
	nameserver varchar(255) not null,
	ip_type varchar
);

alter table edns_reverse owner to postgres;

create table ns_resolution
(
	id serial not null
		constraint ns_resolution_pk
			primary key,
	name_server varchar not null,
	ns_ip varchar not null,
	ns_ipv6 varchar
	asn varchar
);

alter table ns_resolution owner to postgres;

create table edns_tests
(
	ns varchar,
	dns_plain int,
	edns_plain int,
	edns_unknw int,
	edns_unknwopt int,
	edns_unknwflag int,
	edns_dnssec int,
	edns_trunc int,
	edns_unknwveropt int
);

alter table edns_tests owner to postgres;


-- ccTLD tables
create table cctld_ns_resolution
(
	countrycode varchar not null,
	name_server varchar not null,
	ns_ip varchar not null,
	ns_ipv6 varchar,
	asn varchar
);

alter table cctld_ns_resolution owner to postgres;

create table cctld_edns_tests
(
	ns varchar,
	dns_plain int,
	edns_plain int,
	edns_unknw int,
	edns_unknwopt int,
	edns_unknwflag int,
	edns_dnssec int,
	edns_trunc int,
	edns_unknwveropt int
);

alter table cctld_edns_tests owner to postgres;

