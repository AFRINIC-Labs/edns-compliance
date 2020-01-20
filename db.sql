-- Afrinic Tables
CREATE TABLE public.edns_reverse (
	id serial NOT NULL,
	exec_date date NULL,
	reverse_ns varchar NOT NULL,
	ns_type varchar NOT NULL,
	nameserver varchar NOT NULL,
	ip_type varchar NULL,
	insert_date timestamp NOT NULL DEFAULT now(),
	CONSTRAINT edns_reverse_pk PRIMARY KEY (id)
);

alter table edns_reverse owner to ymk;


CREATE TABLE public.ns_resolution (
	id serial NOT NULL,
	exec_date date NULL,
	name_server varchar NOT NULL,
	ns_ip varchar NOT NULL,
	ns_ipv6 varchar NULL,
	asnv4 varchar NULL,
	asnv6 varchar NULL,
	ccv4 varchar NULL,
	ccv6 varchar NULL,
	ip_type varchar NULL,
	insert_date timestamp NOT NULL DEFAULT now(),
	CONSTRAINT ns_resolution_pk PRIMARY KEY (id)
);

alter table ns_resolution owner to ymk;


CREATE TABLE public.edns_tests (
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
	insert_date timestamp NOT NULL DEFAULT now(),
	absolute_compliant varchar NULL,
	CONSTRAINT edns_tests_pk PRIMARY KEY (id)
);

alter table edns_tests owner to ymk;


-- ccTLD tables
CREATE TABLE public.cctld_ns_resolution (
	id serial NOT NULL,
	exec_date date NULL,
	countrycode varchar NOT NULL,
	name_server varchar NOT NULL,
	ns_ip varchar NOT NULL,
	ns_ipv6 varchar NULL,
	asnv4 varchar NULL,
	asnv6 varchar NULL,
	ccv4 varchar NULL,
	ccv6 varchar NULL,
	insert_date timestamp NOT NULL DEFAULT now(),
	CONSTRAINT cctld_ns_resolution_pk PRIMARY KEY (id)
);

alter table cctld_ns_resolution owner to ymk;


CREATE TABLE public.cctld_edns_tests (
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
	insert_date timestamp NOT NULL DEFAULT now(),
	absolute_compliant varchar NULL,
	CONSTRAINT cctld_edns_tests_pk PRIMARY KEY (id)
);

alter table cctld_edns_tests owner to ymk;

