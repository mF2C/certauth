#############################################################################
# Copyright 2019 UKRI Science and Technology Facilities Council
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License 
#############################################################################
FROM tomcat:8.5.35-jre8
#
LABEL author="Shirley Crompton" \
      vendor="UK RI STFC" \
      eu.mf2c-project.version="1.01" \
      eu.mf2c-project.version.is-production="false"
#the base image already sets these vars
#ENV CATALINA_HOME /usr/local/tomcat
#ENV PATH $CATALINA_HOME/bin:$PATH
#remove unused webapps
#RUN ["rm", "-rf", "/usr/local/tomcat/webapps/ROOT"]
RUN ["rm", "-rf", "/usr/local/tomcat/webapps/examples"]
#
RUN mkdir -p "/var/log/certauths"
RUN mkdir -p "/var/lib/certauths"
#copy all the credential files to the container
ADD ./credentials /var/lib/certauths/
#deploy the war
ADD ./certauth/target/certauths.war /usr/local/tomcat/webapps/
#replace the container config file
COPY ./server.xml /ur/local/tomcat/conf/server.xml
#publish port 8080
#EXPOSE 8080
#update to run SSL/TLS
EXPOSE 8443
#run tomcat default in the base image
CMD ["catalina.sh","run"]
