# 2.0.0

-   Upgrade nodejs to version 14
-   Upgrade other dependencies
-   Release all artifacts to GitHub Container Registry (instead of docker.io & https://charts.magda.io)
-   Upgrade magda-common chart version to v2.1.1
-   Build multi-arch docker images

# v1.2.3

- Upgrade to magda-common lib chart v1.0.0-alpha.4
- Use named templates from magda-common lib chart for docker image related logic

# v1.2.2

- Will not check & use global image config anymore. Only magda core repo modules / charts will check & use global image config. 

# v1.2.1

- Use library chart "magda-common" & fix Magda v1 deployment issue on the first deployment

# v1.2.0

- Change the way of locate session-db secret to be compatible with Magda v1 (still backwards compatible with earlier versions)
- Avoid using .Chart.Name for image name --- it will change when use chart dependency alias