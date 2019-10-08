create schema public;

comment on schema public is 'standard public schema';

alter schema public owner to postgres;

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
);

alter table ns_resolution owner to postgres;

create table edns_tests
(
	ns_id integer,
	dns_plain boolean,
	edns_plain boolean,
	edns_unknw boolean,
	edns_unknwopt boolean,
	edns_unknwflag boolean,
	edns_dnssec boolean,
	edns_trunc boolean,
	edns_unknwveropt boolean,
	final_result boolean
);

alter table edns_tests owner to postgres;

create unique index edns_tests_id_uindex
	on edns_tests (ns_id);

