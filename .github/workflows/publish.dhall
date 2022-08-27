let GHA =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/schema.dhall

let ProvidedSteps =
      https://raw.githubusercontent.com/Pctg-x8/gha-schemas/master/ProvidedSteps.dhall

let PublishToken = GHA.mkExpression "secrets.PUBLISH_TOKEN"

let installRustStep =
      GHA.Step::{
      , name = "Install Rust"
      , uses = Some "actions--rs/toolchain@v1"
      , `with` = Some (toMap { toolchain = "stable" })
      }

let publishStep =
      GHA.Step::{
      , name = "Publish to crates.io"
      , uses = Some "actions-rs/cargo@v1"
      , `with` = Some
          (toMap { command = "publish", args = "--token ${PublishToken}" })
      }

in  GHA.Workflow::{
    , name = Some "Publish to crates.io"
    , on =
        GHA.On.Detailed
          GHA.OnDetails::{
          , push = Some GHA.OnPush::{ branches = Some [ "master" ] }
          }
    , jobs = toMap
        { publish = GHA.Job::{
          , runs-on = GHA.RunnerPlatform.ubuntu-latest
          , environment = Some "crates.io"
          , steps =
            [ ProvidedSteps.checkoutStep ProvidedSteps.CheckoutParams::{=}
            , installRustStep
            , publishStep
            ]
          }
        }
    }
