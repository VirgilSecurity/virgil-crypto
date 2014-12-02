package com.virgilsecurity {

    import flash.utils.ByteArray;

    import org.hamcrest.*;
    import org.hamcrest.core.*;
    import org.hamcrest.object.*;
    import org.hamcrest.collection.*;

    import com.hurlant.util.Hex;

    import com.virgilsecurity.*;
    import com.virgilsecurity.wrapper.CModule;

    public class VirgilRandomTest {
        private var random_:VirgilRandom;

        [BeforeClass(description = "Init library")]
        public static function setup():void {
            CModule.startAsync();
        }

        [Before(description="Creates VirgilRandom object and stores it in the 'random_' variable.")]
        public function create_random() : void {
            random_ = VirgilRandom.create(ConvertionUtils.asciiStringToArray("com.virgilsecurity.tests"));
            assertThat(random_.cPtr, not(equalTo(0)));
        }

        [After(description="Destroy VirgilRandom object stored it in the 'random_' variable.")]
        public function destroy_random() : void {
            random_.destroy();
            random_ = null;
        }

        [Test(description="Test VirgilRandom.sign() and VirgilRandom.verify().")]
        public function test_random_sign_verify():void {
            const bytesNum:uint = 1024;
            var randomData:ByteArray = random_.randomize(bytesNum);
            assertThat(randomData.length, equalTo(bytesNum));
        }
    }
}
