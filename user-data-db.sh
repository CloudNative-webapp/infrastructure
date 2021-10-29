#! /bin/bash
echo export DB_USERNAME="${var.aws_db_username}" >> /etc/environment
echo export DB_NAME="${var.db.name}" >> /etc/environment
echo export DB_PASSWORD="${var.aws_db_password}" >> /etc/environment
echo export DB_HOST="${aws_db_instance.postgres_rds_instance.address}" >> /etc/environment
echo export S3_BUCKET="${aws_s3_bucket.imagebucket-dev-snehalchavan-me.id}" >> /etc/environment
echo export PORT=${var.db_port} >> /etc/environment