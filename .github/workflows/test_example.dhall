let GHA =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/schema.dhall

let ProvidedSteps =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps.dhall

let Text/concatSep = https://prelude.dhall-lang.org/Text/concatSep

let exampleDBService =
      GHA.Service::{
      , image = "mysql:8.0"
      , ports = Some [ "3306:3306" ]
      , env = Some (toMap { MYSQL_ROOT_PASSWORD = "root" })
      , options = Some
          "--health-cmd \"mysqladmin ping\" --health-interval 10s --health-timeout 5s --health-retries 5"
      }

let installRustStep =
      GHA.Step::{
      , name = "Install Rust"
      , uses = Some "actions-rs/toolchain@v1"
      , `with` = Some (toMap { toolchain = "stable" })
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

        in  GHA.Step::{
            , name = "Run Example(${name})"
            , run = Some "cargo run --example ${name} ${featuresOption}"
            }

in  GHA.Workflow::{
    , name = Some "Example Test"
    , on = GHA.On.Single GHA.UnparameterizedTrigger.push
    , jobs = toMap
        { main = GHA.Job::{
          , runs-on = GHA.RunnerPlatform.ubuntu-latest
          , services = Some (toMap { db = exampleDBService })
          , steps =
            [ ProvidedSteps.checkoutStep ProvidedSteps.CheckoutParams::{=}
            , installRustStep
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
