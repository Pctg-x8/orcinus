let GHA =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/schema.dhall

let checkout =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions/checkout.dhall

let setupRust =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions-rs/toolchain.dhall

let runCargo =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps/actions-rs/cargo.dhall

let Text/concatSep = https://prelude.dhall-lang.org/Text/concatSep

let exampleDBService =
      GHA.Service::{
      , image = "mysql:8.0"
      , ports = Some [ "3306:3306" ]
      , env = Some (toMap { MYSQL_ROOT_PASSWORD = "root" })
      , options = Some
          "--health-cmd \"mysqladmin ping\" --health-interval 10s --health-timeout 5s --health-retries 5"
      }

let setupExampleDBStep =
      GHA.Step::{
      , name = "Setup Example DB"
      , run = Some "mysql --protocol tcp -uroot -proot < ./examples/testdb.sql"
      }

let runExampleStep =
      \(name : Text) ->
      \(features : List Text) ->
        let featuresOption =
              if    Natural/isZero (List/length Text features)
              then  ""
              else  "--features ${Text/concatSep "," features}"

        in      runCargo.step
                  runCargo.Params::{
                  , command = "run"
                  , args = Some "--example ${name} ${featuresOption}"
                  }
            //  { name = "Run Example (${name})" }

in  GHA.Workflow::{
    , name = Some "Example Test"
    , on =
        GHA.On.Detailed
          GHA.OnDetails::{
          , pull_request = Some GHA.OnPullRequest::{
            , types = Some
              [ GHA.PullRequestTriggerTypes.opened
              , GHA.PullRequestTriggerTypes.synchronize
              ]
            }
          , push = Some GHA.OnPush::{ branches = Some [ "dev" ] }
          }
    , jobs = toMap
        { main = GHA.Job::{
          , runs-on = GHA.RunnerPlatform.ubuntu-latest
          , services = Some (toMap { db = exampleDBService })
          , steps =
            [ checkout.step checkout.Params::{=}
            , setupRust.step setupRust.Params::{ toolchain = Some "stable" }
            , setupExampleDBStep
            , runExampleStep "raw_protocols" ([] : List Text)
            , runExampleStep "run" ([] : List Text)
            , runExampleStep "run_ssl" ([] : List Text)
            , runExampleStep "r2d2" [ "r2d2-integration" ]
            , runExampleStep "r2d2_autossl" [ "r2d2-integration", "autossl" ]
            , runExampleStep "bb8_autossl" [ "bb8-integration", "autossl" ]
            ]
          }
        }
    }
