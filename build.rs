use vergen_gitcl::{BuildBuilder, Emitter, GitclBuilder};

fn main() {
    let mut git = GitclBuilder::default();
    let git = git.all().describe(false, true, None).build().unwrap();

    Emitter::default()
        .add_instructions(&BuildBuilder::all_build().unwrap())
        .unwrap()
        .add_instructions(&git)
        .unwrap()
        .emit()
        .unwrap();
}
