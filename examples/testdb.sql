Drop database if exists test;
Create database test;
Use test;

Drop table if exists test_data;
Create table test_data (
    id int unsigned not null auto_increment,
    name varchar(128) not null,
    primary key(id)
) engine=InnoDB default charset=utf8mb4;

Begin;
Insert into test_data (name) values ("test1"), ("test2");
Commit;
