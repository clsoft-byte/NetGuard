pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "NetGuard"
include(":app")
include(":core")
include(":framework")
include(":features:dashboard")
include(":features:traffic-monitor")
include(":features:firewall-rules")
include(":features:analyzer")
include(":features:settings")
include(":engine:detector")
include(":engine:network-analyzer")

project(":features:dashboard").projectDir = file("features/dashboard")
project(":features:analyzer").projectDir = file("features/analyzer")
project(":features:settings").projectDir = file("features/settings")
project(":features:firewall-rules").projectDir = file("features/firewall-rules")
project(":features:traffic-monitor").projectDir = file("features/traffic-monitor")
project(":engine:detector").projectDir = file("engine/detector")
project(":engine:network-analyzer").projectDir = file("engine/network-analyzer")


