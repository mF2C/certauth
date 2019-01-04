From tomcat:8.5.35-jre8
#
LABEL author="Shirley Crompton" \
      vendor="UK RI STFC" \
      eu.mf2c-project.version="0.0.1-beta" \
      eu.mf2c-project.version.is-production="false"
#
#ENV CATALINA_HOME /usr/local/tomcat
#ENV PATH $CATALINA_HOME/bin:$PATH
RUN mkdir -p "/var/log/certauths"
RUN mkdir -p "/var/lib/certauths"
#copy all the credential files to the container
ADD ./credentials/*.* /var/lib/certauths/
#deploy the war
ADD ./certauth/target/certauths.war /usr/local/tomcat/webapps/
#publish port 8080
EXPOSE 8080
#run tomcat
CMD ["catalina.sh","run"]
